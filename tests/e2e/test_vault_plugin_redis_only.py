# -*- coding: utf-8 -*-
"""Location: ./tests/e2e/test_vault_plugin_redis_only.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Adrian Popa

Simplified E2E test for Vault Plugin with Redis caching (no MCP server).

This test validates vault plugin caching with real Redis without the complexity
of starting an MCP server.
"""

import json
import os
import tempfile
import time
from typing import Any, Dict
from unittest.mock import patch as mock_patch

import pytest
import pytest_asyncio
from pydantic import SecretStr
from unittest.mock import MagicMock

# Patch bootstrap_db before importing main
with mock_patch("mcpgateway.bootstrap_db.main"):
    from mcpgateway.config import settings

# Import vault plugin components
from mcpgateway.plugins.framework.hooks.http import HttpHeaderPayload
from mcpgateway.plugins.framework.hooks.tools import ToolPreInvokePayload
from mcpgateway.plugins.framework.models import PluginContext
from plugins.vault.vault_plugin import Vault

TEST_USER = "vault_test_user"
JWT_SECRET = "e2e-vault-test-jwt-secret-key-with-minimum-32-bytes"
JWT_ALGORITHM = "HS256"
VAULT_API_KEY = "test-vault-api-key-12345"

if hasattr(settings.jwt_secret_key, "get_secret_value"):
    settings.jwt_secret_key = SecretStr(JWT_SECRET)
else:
    settings.jwt_secret_key = JWT_SECRET


class MockVaultProxy:
    """Mock Vault proxy server for testing unwrap functionality."""
    
    def __init__(self):
        self.wrapped_tokens = {
            "hvs.wrapped_github_token": "ghp_actual_github_token_12345",
            "hvs.wrapped_localhost_token": "test_localhost_token_abcdef",
        }
        self.unwrapped_tokens: set[str] = set()
        self.unwrap_call_count = 0
    
    async def async_unwrap_secret(self, token_name: str, vault_token: str) -> Dict[str, Any]:
        """Mock unwrap secret function."""
        self.unwrap_call_count += 1
        
        # Check if token was already unwrapped (single-use)
        if vault_token in self.unwrapped_tokens:
            raise Exception(f"Token already unwrapped: {vault_token}")
        
        # Check if token exists
        if vault_token not in self.wrapped_tokens:
            raise Exception(f"Token not found: {vault_token}")
        
        # Unwrap the token
        secret_value = self.wrapped_tokens[vault_token]
        self.unwrapped_tokens.add(vault_token)
        
        return {
            "key": token_name,
            "value": secret_value
        }
    
    def reset(self):
        """Reset unwrapped tokens for testing."""
        self.unwrapped_tokens.clear()
        self.unwrap_call_count = 0


@pytest.fixture
def mock_vault():
    """Create mock vault proxy."""
    return MockVaultProxy()


@pytest.fixture
def plugin_context():
    """Create plugin context with gateway metadata."""
    context = MagicMock(spec=PluginContext)
    context.global_context = MagicMock()
    context.global_context.server_id = "test-server-id"
    context.global_context.metadata = {
        "gateway": {
            "tags": [{"label": "system:localhost"}]
        }
    }
    return context


@pytest.fixture
def vault_plugin_unwrap():
    """Create vault plugin with UNWRAP mode."""
    from mcpgateway.plugins.framework.models import PluginConfig
    config = PluginConfig(
        name="VaultPlugin",
        kind="plugins.vault.vault_plugin.Vault",
        hooks=["tool_pre_invoke"],
        config={
            "vault_handling": "unwrap",
            "system_handling": "tag",
            "vault_header_name": "X-Vault-Tokens",
            "vault_session_header": "X-Vault-Session-ID",
            "unwrap_cache_ttl_seconds": 600,
            "encrypt_cache": False,  # Disable encryption for simpler testing
        }
    )
    return Vault(config)


@pytest.mark.asyncio
async def test_vault_plugin_redis_caching(vault_plugin_unwrap, plugin_context, mock_vault):
    """Test vault plugin with Redis caching (no MCP server).
    
    Note: Environment variables (REDIS_URL, CACHE_TYPE, etc.) are set in pyproject.toml
    via pytest-env plugin, ensuring they're available before config module loads.
    """
    
    # Mock the vault_proxy.async_unwrap_secret function
    with mock_patch("plugins.vault.vault_proxy.async_unwrap_secret", new=mock_vault.async_unwrap_secret):
        session_id = "test-session-redis-12345"
        vault_tokens = {"localhost": "hvs.wrapped_localhost_token"}
        
        print(f"\n🚀 Testing vault plugin with Redis caching")
        print(f"   Session ID: {session_id}")
        print(f"   Redis URL: redis://localhost:6379/0")
        
        # Test 1: First call (should unwrap and cache)
        print("\n📡 Test 1: First call (should unwrap and cache in Redis)")
        headers1 = {
            "X-Vault-Tokens": json.dumps(vault_tokens),
            "X-Vault-Session-ID": session_id
        }
        
        payload1 = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root=headers1)
        )
        
        result1 = await vault_plugin_unwrap.tool_pre_invoke(payload1, plugin_context)
        
        assert result1.modified_payload is not None
        modified_headers1 = result1.modified_payload.headers.model_dump()
        
        # Verify Authorization header was set
        assert "Authorization" in modified_headers1, "Authorization header not set"
        assert "test_localhost_token_abcdef" in modified_headers1["Authorization"]
        
        # Verify X-Vault-Tokens was removed
        assert "X-Vault-Tokens" not in modified_headers1, "X-Vault-Tokens not removed"
        
        print(f"✅ First call: Token unwrapped and cached")
        print(f"   Unwrap call count: {mock_vault.unwrap_call_count}")
        print(f"   Authorization: {modified_headers1.get('Authorization', 'N/A')[:50]}...")
        
        # Verify unwrap was called once
        assert mock_vault.unwrap_call_count == 1, f"Expected 1 unwrap call, got {mock_vault.unwrap_call_count}"
        
        # Test 2: Second call with same session (should use Redis cache)
        print("\n📡 Test 2: Second call (should use Redis cache, no unwrap)")
        headers2 = {
            "X-Vault-Tokens": json.dumps(vault_tokens),
            "X-Vault-Session-ID": session_id
        }
        
        payload2 = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root=headers2)
        )
        
        result2 = await vault_plugin_unwrap.tool_pre_invoke(payload2, plugin_context)
        
        assert result2.modified_payload is not None
        modified_headers2 = result2.modified_payload.headers.model_dump()
        
        # Verify same token is used
        assert "Authorization" in modified_headers2
        assert "test_localhost_token_abcdef" in modified_headers2["Authorization"]
        
        print(f"✅ Second call: Used Redis cached token")
        print(f"   Unwrap call count: {mock_vault.unwrap_call_count}")
        
        # Verify unwrap was NOT called again (cached)
        assert mock_vault.unwrap_call_count == 1, f"Expected 1 unwrap call (cached), got {mock_vault.unwrap_call_count}"
        
        # Test 3: Third call (verify Redis cache persistence)
        print("\n📡 Test 3: Third call (verify Redis cache still working)")
        headers3 = {
            "X-Vault-Tokens": json.dumps(vault_tokens),
            "X-Vault-Session-ID": session_id
        }
        
        payload3 = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root=headers3)
        )
        
        result3 = await vault_plugin_unwrap.tool_pre_invoke(payload3, plugin_context)
        
        assert result3.modified_payload is not None
        modified_headers3 = result3.modified_payload.headers.model_dump()
        
        assert "Authorization" in modified_headers3
        assert "test_localhost_token_abcdef" in modified_headers3["Authorization"]
        
        print(f"✅ Third call: Redis cache still working")
        print(f"   Unwrap call count: {mock_vault.unwrap_call_count}")
        
        # Still only 1 unwrap call
        assert mock_vault.unwrap_call_count == 1, f"Expected 1 unwrap call (cached), got {mock_vault.unwrap_call_count}"
        
        print(f"\n📊 Final stats:")
        print(f"   Total unwrap calls: {mock_vault.unwrap_call_count}")
        print(f"   Tokens unwrapped: {len(mock_vault.unwrapped_tokens)}")
        print(f"   Redis caching: ✅ Working")
        print(f"   Cache hits: 2 (second and third calls)")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

# Made with Bob
