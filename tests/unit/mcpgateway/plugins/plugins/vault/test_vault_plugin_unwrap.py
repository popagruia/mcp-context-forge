# -*- coding: utf-8 -*-
"""Tests for Vault plugin UNWRAP mode.

Copyright 2026
SPDX-License-Identifier: Apache-2.0
"""

# Standard
import json
from unittest.mock import AsyncMock, MagicMock, patch

# Third-Party
import pytest

# First-Party
from mcpgateway.plugins.framework import (
    GlobalContext,
    HttpHeaderPayload,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
)
from plugins.vault.vault_plugin import Vault, VaultConfig, VaultHandling


# Mock vault_proxy module
class MockVaultProxy:
    """Mock vault proxy for testing."""

    @staticmethod
    async def async_unwrap_secret(token_name: str, vault_token: str) -> str:
        """Mock unwrap implementation."""
        return f"unwrapped_{vault_token}"


@pytest.fixture
def vault_plugin_unwrap():
    """Create Vault plugin with UNWRAP mode."""
    config = PluginConfig(
        name="vault",
        enabled=True,
        config={
            "vault_handling": "unwrap",
            "system_handling": "tag",
            "system_tag_prefix": "system",
            "vault_header_name": "X-Vault-Tokens",
            "vault_session_header": "X-Vault-Session-ID",
            "unwrap_cache_ttl_seconds": 600.0,
        },
    )
    return Vault(config)


@pytest.fixture
def plugin_context():
    """Create plugin context with gateway metadata."""
    global_ctx = GlobalContext(
        request_id="test-request-123",
        server_id="test-server-456",
        metadata={
            "gateway": MagicMock(
                tags=[
                    {"id": "1", "label": "system:github.com"},
                    {"id": "2", "label": "AUTH_HEADER:X-GitHub-Token"},
                ]
            )
        },
    )
    return PluginContext(global_context=global_ctx)


@pytest.fixture
def tool_payload_unwrap():
    """Create tool payload with wrapped token and session ID."""
    headers = {
        "X-Vault-Session-ID": "agent-chat-session-123",
        "X-Vault-Tokens": json.dumps({"github.com": "wrapped_token_xyz"}),
    }
    return ToolPreInvokePayload(
        name="test_tool",
        arguments={"arg1": "value1"},
        headers=HttpHeaderPayload(root=headers),
    )


@pytest.mark.asyncio
async def test_unwrap_mode_first_call(vault_plugin_unwrap, plugin_context, tool_payload_unwrap):
    """Test UNWRAP mode on first call (cache miss)."""
    # Mock Redis client
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)  # Cache miss
    mock_redis.set = AsyncMock(return_value=True)  # Lock acquired
    mock_redis.setex = AsyncMock()  # Cache write
    mock_redis.delete = AsyncMock()  # Lock release

    # Mock vault_proxy module
    mock_vault_proxy = MagicMock()
    mock_vault_proxy.async_unwrap_secret = AsyncMock(return_value="unwrapped_token_abc")

    with patch("plugins.vault.vault_plugin.get_redis_client", return_value=mock_redis):
        with patch("plugins.vault.vault_plugin.vault_proxy", mock_vault_proxy):
            result = await vault_plugin_unwrap.tool_pre_invoke(tool_payload_unwrap, plugin_context)

            # Verify unwrap was called
            mock_vault_proxy.async_unwrap_secret.assert_called_once_with(
                token_name="github.com",
                vault_token="wrapped_token_xyz"
            )

            # Verify token was cached
            assert mock_redis.setex.called
            cache_key_arg = mock_redis.setex.call_args[0][0]
            assert cache_key_arg.startswith("mcpgw:vault:unwrapped:")
            assert mock_redis.setex.call_args[0][1] == 600  # TTL
            assert mock_redis.setex.call_args[0][2] == "unwrapped_token_abc"

            # Verify Authorization header was set
            assert result.modified_payload is not None
            headers = result.modified_payload.headers.model_dump()
            assert headers["Authorization"] == "Bearer unwrapped_token_abc"
            assert "X-Vault-Tokens" not in headers  # Vault header removed


@pytest.mark.asyncio
async def test_unwrap_mode_cache_hit(vault_plugin_unwrap, plugin_context, tool_payload_unwrap):
    """Test UNWRAP mode on subsequent call (cache hit)."""
    # Mock Redis client with cached token
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value="cached_unwrapped_token")

    # Mock vault_proxy module
    mock_vault_proxy = MagicMock()
    mock_vault_proxy.async_unwrap_secret = AsyncMock()

    with patch("plugins.vault.vault_plugin.get_redis_client", return_value=mock_redis):
        with patch("plugins.vault.vault_plugin.vault_proxy", mock_vault_proxy):
            result = await vault_plugin_unwrap.tool_pre_invoke(tool_payload_unwrap, plugin_context)

            # Verify unwrap was NOT called (cache hit)
            mock_vault_proxy.async_unwrap_secret.assert_not_called()

            # Verify cached token was used
            assert result.modified_payload is not None
            headers = result.modified_payload.headers.model_dump()
            assert headers["Authorization"] == "Bearer cached_unwrapped_token"


@pytest.mark.asyncio
async def test_unwrap_mode_missing_session_id(vault_plugin_unwrap, plugin_context):
    """Test UNWRAP mode fails without session ID."""
    # Payload without session ID
    headers = {
        "X-Vault-Tokens": json.dumps({"github.com": "wrapped_token_xyz"}),
    }
    payload = ToolPreInvokePayload(
        name="test_tool",
        arguments={"arg1": "value1"},
        headers=HttpHeaderPayload(root=headers),
    )

    result = await vault_plugin_unwrap.tool_pre_invoke(payload, plugin_context)

    # Should return empty result (no modification)
    assert result.modified_payload is None


@pytest.mark.asyncio
async def test_unwrap_mode_distributed_lock(vault_plugin_unwrap, plugin_context, tool_payload_unwrap):
    """Test distributed lock prevents duplicate unwrapping."""
    # Mock Redis client - lock acquisition fails (another instance has it)
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=[
        None,  # First check: cache miss
        None,  # After lock fail: still miss
        "unwrapped_by_other_instance",  # Poll 1: got it!
    ])
    mock_redis.set = AsyncMock(return_value=False)  # Lock NOT acquired

    # Mock vault_proxy module
    mock_vault_proxy = MagicMock()
    mock_vault_proxy.async_unwrap_secret = AsyncMock()

    with patch("plugins.vault.vault_plugin.get_redis_client", return_value=mock_redis):
        with patch("plugins.vault.vault_plugin.vault_proxy", mock_vault_proxy):
            with patch("asyncio.sleep", new_callable=AsyncMock):  # Speed up polling
                result = await vault_plugin_unwrap.tool_pre_invoke(tool_payload_unwrap, plugin_context)

                # Verify unwrap was NOT called (other instance did it)
                mock_vault_proxy.async_unwrap_secret.assert_not_called()

                # Verify we got the token from other instance
                assert result.modified_payload is not None
                headers = result.modified_payload.headers.model_dump()
                assert headers["Authorization"] == "Bearer unwrapped_by_other_instance"


@pytest.mark.asyncio
async def test_unwrap_mode_no_redis_fallback(vault_plugin_unwrap, plugin_context, tool_payload_unwrap):
    """Test UNWRAP mode falls back to direct unwrap when Redis unavailable."""
    # Mock vault_proxy module
    mock_vault_proxy = MagicMock()
    mock_vault_proxy.async_unwrap_secret = AsyncMock(return_value="unwrapped_no_cache")

    # Mock Redis unavailable
    with patch("plugins.vault.vault_plugin.get_redis_client", return_value=None):
        with patch("plugins.vault.vault_plugin.vault_proxy", mock_vault_proxy):
            result = await vault_plugin_unwrap.tool_pre_invoke(tool_payload_unwrap, plugin_context)

            # Verify unwrap was called directly
            mock_vault_proxy.async_unwrap_secret.assert_called_once()

            # Verify token was used
            assert result.modified_payload is not None
            headers = result.modified_payload.headers.model_dump()
            assert headers["Authorization"] == "Bearer unwrapped_no_cache"


@pytest.mark.asyncio
async def test_unwrap_mode_different_sessions_isolated(vault_plugin_unwrap, plugin_context):
    """Test different sessions get different cache entries."""
    # Mock Redis client
    mock_redis = AsyncMock()
    cache_storage = {}

    async def mock_get(key):
        return cache_storage.get(key)

    async def mock_setex(key, ttl, value):
        cache_storage[key] = value

    mock_redis.get = mock_get
    mock_redis.set = AsyncMock(return_value=True)
    mock_redis.setex = mock_setex
    mock_redis.delete = AsyncMock()

    # Mock vault_proxy module
    mock_vault_proxy = MagicMock()
    unwrap_call_count = [0]

    async def mock_unwrap(token_name, vault_token):
        unwrap_call_count[0] += 1
        return f"unwrapped_session_{unwrap_call_count[0]}"

    mock_vault_proxy.async_unwrap_secret = mock_unwrap

    with patch("plugins.vault.vault_plugin.get_redis_client", return_value=mock_redis):
        with patch("plugins.vault.vault_plugin.vault_proxy", mock_vault_proxy):
            # Session 1
            headers1 = {
                "X-Vault-Session-ID": "session-1",
                "X-Vault-Tokens": json.dumps({"github.com": "wrapped_token"}),
            }
            payload1 = ToolPreInvokePayload(
                name="test_tool",
                arguments={},
                headers=HttpHeaderPayload(root=headers1),
            )

            result1 = await vault_plugin_unwrap.tool_pre_invoke(payload1, plugin_context)
            assert result1.modified_payload.headers.model_dump()["Authorization"] == "Bearer unwrapped_session_1"

            # Session 2 (different session ID, same wrapped token)
            headers2 = {
                "X-Vault-Session-ID": "session-2",
                "X-Vault-Tokens": json.dumps({"github.com": "wrapped_token"}),
            }
            payload2 = ToolPreInvokePayload(
                name="test_tool",
                arguments={},
                headers=HttpHeaderPayload(root=headers2),
            )

            result2 = await vault_plugin_unwrap.tool_pre_invoke(payload2, plugin_context)
            assert result2.modified_payload.headers.model_dump()["Authorization"] == "Bearer unwrapped_session_2"

            # Verify unwrap was called twice (different sessions)
            assert unwrap_call_count[0] == 2


@pytest.mark.asyncio
async def test_cache_key_generation(vault_plugin_unwrap):
    """Test cache key generation is consistent."""
    session_id = "test-session-123"
    wrapped_token = "wrapped_token_xyz"

    key1 = vault_plugin_unwrap._get_cache_key(session_id, wrapped_token)
    key2 = vault_plugin_unwrap._get_cache_key(session_id, wrapped_token)

    # Same inputs should produce same key
    assert key1 == key2
    assert len(key1) == 64  # SHA-256 hex digest

    # Different inputs should produce different keys
    key3 = vault_plugin_unwrap._get_cache_key("different-session", wrapped_token)
    assert key1 != key3


@pytest.mark.asyncio
async def test_unwrap_mode_redis_error_handling(vault_plugin_unwrap, plugin_context, tool_payload_unwrap):
    """Test graceful handling of Redis errors."""
    # Mock Redis client that raises errors
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=Exception("Redis connection error"))
    mock_redis.set = AsyncMock(side_effect=Exception("Redis connection error"))

    # Mock vault_proxy module
    mock_vault_proxy = MagicMock()
    mock_vault_proxy.async_unwrap_secret = AsyncMock(return_value="unwrapped_despite_redis_error")

    with patch("plugins.vault.vault_plugin.get_redis_client", return_value=mock_redis):
        with patch("plugins.vault.vault_plugin.vault_proxy", mock_vault_proxy):
            result = await vault_plugin_unwrap.tool_pre_invoke(tool_payload_unwrap, plugin_context)

            # Should still unwrap successfully
            mock_vault_proxy.async_unwrap_secret.assert_called_once()
            assert result.modified_payload is not None
            headers = result.modified_payload.headers.model_dump()
            assert headers["Authorization"] == "Bearer unwrapped_despite_redis_error"

# Made with Bob
