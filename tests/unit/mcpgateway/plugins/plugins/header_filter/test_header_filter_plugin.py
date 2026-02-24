# -*- coding: utf-8 -*-
"""Location: ./tests/unit/mcpgateway/plugins/plugins/header_filter/test_header_filter_plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Adrian Popa

Unit tests for Header Filter Plugin functionality.
"""

# Third-Party
import pytest

# First-Party
from mcpgateway.plugins.framework import (
    GlobalContext,
    HttpHeaderPayload,
    PluginConfig,
    PluginContext,
    PluginMode,
    ToolHookType,
    ToolPreInvokePayload,
)

# Import the Header Filter plugin
from plugins.header_filter.header_filter_plugin import HeaderFilter


class TestHeaderFilterPluginFunctionality:
    """Unit tests for Header Filter plugin functionality."""

    @pytest.fixture
    def plugin_config(self) -> PluginConfig:
        """Create a test plugin configuration."""
        return PluginConfig(
            name="TestHeaderFilter",
            description="Test Header Filter Plugin",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test", "header_filter"],
            mode=PluginMode.ENFORCE,
            priority=20,
            config={
                "filter_headers": ["Authorization", "Cookie", "X-API-Key"],
                "log_filtered_headers": True,
                "allow_passthrough_headers": [],
            },
        )

    @pytest.fixture
    def plugin_context(self) -> PluginContext:
        """Create a test plugin context."""
        global_context = GlobalContext(request_id="test-1")
        return PluginContext(global_context=global_context)

    @pytest.mark.asyncio
    async def test_no_headers_returns_empty_result(self, plugin_config, plugin_context):
        """Test that missing headers returns empty result."""
        plugin = HeaderFilter(plugin_config)

        # Create payload without headers
        payload = ToolPreInvokePayload(name="test_tool", arguments={}, headers=None)

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is None
        assert result.continue_processing

    @pytest.mark.asyncio
    async def test_authorization_header_is_filtered(self, plugin_config, plugin_context):
        """Test that Authorization header is filtered."""
        plugin = HeaderFilter(plugin_config)

        # Create payload with Authorization header
        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root={"Content-Type": "application/json", "Authorization": "Bearer secret_token"}),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        assert "Authorization" not in result.modified_payload.headers.root
        assert "Content-Type" in result.modified_payload.headers.root
        assert result.continue_processing

    @pytest.mark.asyncio
    async def test_cookie_header_is_filtered(self, plugin_config, plugin_context):
        """Test that Cookie header is filtered."""
        plugin = HeaderFilter(plugin_config)

        # Create payload with Cookie header
        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root={"Content-Type": "application/json", "Cookie": "session=abc123"}),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        assert "Cookie" not in result.modified_payload.headers.root
        assert "Content-Type" in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_multiple_sensitive_headers_filtered(self, plugin_config, plugin_context):
        """Test that multiple sensitive headers are filtered."""
        plugin = HeaderFilter(plugin_config)

        # Create payload with multiple sensitive headers
        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(
                root={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer token",
                    "Cookie": "session=xyz",
                    "X-API-Key": "secret_key",
                    "User-Agent": "TestClient/1.0",
                }
            ),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # Sensitive headers should be removed
        assert "Authorization" not in result.modified_payload.headers.root
        assert "Cookie" not in result.modified_payload.headers.root
        assert "X-API-Key" not in result.modified_payload.headers.root
        # Safe headers should remain
        assert "Content-Type" in result.modified_payload.headers.root
        assert "User-Agent" in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_case_insensitive_filtering(self, plugin_config, plugin_context):
        """Test that header filtering is case-insensitive."""
        plugin = HeaderFilter(plugin_config)

        # Create payload with mixed-case headers
        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(
                root={
                    "content-type": "application/json",
                    "authorization": "Bearer token",  # lowercase
                    "COOKIE": "session=xyz",  # uppercase
                    "X-Api-Key": "secret",  # mixed case
                }
            ),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # All sensitive headers should be removed regardless of case
        assert "authorization" not in result.modified_payload.headers.root
        assert "COOKIE" not in result.modified_payload.headers.root
        assert "X-Api-Key" not in result.modified_payload.headers.root
        # Safe header should remain
        assert "content-type" in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_passthrough_headers_not_filtered(self, plugin_context):
        """Test that passthrough headers are not filtered even if in filter list."""
        # Create config with passthrough headers
        config = PluginConfig(
            name="TestHeaderFilter",
            description="Test",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test"],
            mode=PluginMode.ENFORCE,
            priority=20,
            config={
                "filter_headers": ["Authorization", "Cookie"],
                "allow_passthrough_headers": ["Authorization"],  # Allow Authorization through
            },
        )

        plugin = HeaderFilter(config)

        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root={"Authorization": "Bearer token", "Cookie": "session=xyz"}),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # Authorization should pass through
        assert "Authorization" in result.modified_payload.headers.root
        # Cookie should still be filtered
        assert "Cookie" not in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_no_filtered_headers_returns_empty_result(self, plugin_config, plugin_context):
        """Test that when no headers are filtered, empty result is returned."""
        plugin = HeaderFilter(plugin_config)

        # Create payload with only safe headers
        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root={"Content-Type": "application/json", "User-Agent": "TestClient/1.0"}),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        # No headers were filtered, so no modification needed
        assert result.modified_payload is None
        assert result.continue_processing

    @pytest.mark.asyncio
    async def test_empty_headers_dict_returns_empty_result(self, plugin_config, plugin_context):
        """Test that empty headers dict returns empty result."""
        plugin = HeaderFilter(plugin_config)

        # Create payload with empty headers
        payload = ToolPreInvokePayload(name="test_tool", arguments={}, headers=HttpHeaderPayload(root={}))

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is None
        assert result.continue_processing

    @pytest.mark.asyncio
    async def test_default_config_when_config_invalid(self, plugin_context):
        """Test that plugin uses default config when provided config is invalid."""
        # Create config with invalid config data
        config = PluginConfig(
            name="TestHeaderFilter",
            description="Test",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test"],
            mode=PluginMode.ENFORCE,
            priority=20,
            config={"invalid_key": "invalid_value"},  # Invalid config
        )

        plugin = HeaderFilter(config)

        # Plugin should still work with default config
        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(root={"Authorization": "Bearer token", "Content-Type": "application/json"}),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        # Default config should filter Authorization
        assert result.modified_payload is not None
        assert "Authorization" not in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_filter_headers_method_returns_correct_tuple(self, plugin_config):
        """Test that _filter_headers method returns correct tuple."""
        plugin = HeaderFilter(plugin_config)

        headers = {"Content-Type": "application/json", "Authorization": "Bearer token", "Cookie": "session=xyz"}

        filtered, removed = plugin._filter_headers(headers, "test:context")

        # Check filtered headers
        assert "Content-Type" in filtered
        assert "Authorization" not in filtered
        assert "Cookie" not in filtered

        # Check removed list
        assert "Authorization" in removed
        assert "Cookie" in removed
        assert len(removed) == 2

    @pytest.mark.asyncio
    async def test_passthrough_for_vault_integration(self, plugin_context):
        """Test passthrough scenario: Vault plugin manages Authorization, filter manages others."""
        # Simulate scenario where Vault plugin handles Authorization
        # but we want to filter other sensitive headers
        config = PluginConfig(
            name="TestHeaderFilter",
            description="Test",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test"],
            mode=PluginMode.ENFORCE,
            priority=20,
            config={
                "filter_headers": ["Authorization", "Cookie", "X-API-Key"],
                "allow_passthrough_headers": ["Authorization"],  # Vault manages this
            },
        )

        plugin = HeaderFilter(config)

        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(
                root={
                    "Authorization": "Bearer vault_token",  # From Vault plugin
                    "Cookie": "session=abc",
                    "X-API-Key": "secret_key",
                    "Content-Type": "application/json",
                }
            ),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # Authorization passes through (Vault manages it)
        assert "Authorization" in result.modified_payload.headers.root
        assert result.modified_payload.headers.root["Authorization"] == "Bearer vault_token"
        # Other sensitive headers are filtered
        assert "Cookie" not in result.modified_payload.headers.root
        assert "X-API-Key" not in result.modified_payload.headers.root
        # Safe headers remain
        assert "Content-Type" in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_gradual_rollout_scenario(self, plugin_context):
        """Test gradual rollout: filter most headers but allow some during testing."""
        # Scenario: Rolling out filtering gradually
        config = PluginConfig(
            name="TestHeaderFilter",
            description="Test",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test"],
            mode=PluginMode.PERMISSIVE,  # Permissive mode for testing
            priority=20,
            config={
                "filter_headers": ["Authorization", "Cookie", "X-Custom-Token", "X-API-Key"],
                "allow_passthrough_headers": ["X-Custom-Token"],  # Temporary exception during testing
            },
        )

        plugin = HeaderFilter(config)

        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(
                root={
                    "Authorization": "Bearer token",
                    "Cookie": "session=xyz",
                    "X-Custom-Token": "custom_value",  # Allowed during testing
                    "X-API-Key": "api_key",
                }
            ),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # X-Custom-Token passes through (temporary exception)
        assert "X-Custom-Token" in result.modified_payload.headers.root
        # Other sensitive headers are filtered
        assert "Authorization" not in result.modified_payload.headers.root
        assert "Cookie" not in result.modified_payload.headers.root
        assert "X-API-Key" not in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_multiple_passthrough_headers(self, plugin_context):
        """Test multiple headers in passthrough list."""
        config = PluginConfig(
            name="TestHeaderFilter",
            description="Test",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test"],
            mode=PluginMode.ENFORCE,
            priority=20,
            config={
                "filter_headers": ["Authorization", "Cookie", "X-API-Key", "X-Custom-Header"],
                "allow_passthrough_headers": ["Authorization", "X-Custom-Header"],  # Multiple exceptions
            },
        )

        plugin = HeaderFilter(config)

        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(
                root={
                    "Authorization": "Bearer token",
                    "Cookie": "session=xyz",
                    "X-API-Key": "api_key",
                    "X-Custom-Header": "custom_value",
                }
            ),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # Both passthrough headers remain
        assert "Authorization" in result.modified_payload.headers.root
        assert "X-Custom-Header" in result.modified_payload.headers.root
        # Other sensitive headers are filtered
        assert "Cookie" not in result.modified_payload.headers.root
        assert "X-API-Key" not in result.modified_payload.headers.root

    @pytest.mark.asyncio
    async def test_passthrough_case_insensitive(self, plugin_context):
        """Test that passthrough headers work case-insensitively."""
        config = PluginConfig(
            name="TestHeaderFilter",
            description="Test",
            author="Test",
            kind="plugins.header_filter.header_filter_plugin.HeaderFilter",
            version="1.0",
            hooks=[ToolHookType.TOOL_PRE_INVOKE],
            tags=["test"],
            mode=PluginMode.ENFORCE,
            priority=20,
            config={
                "filter_headers": ["Authorization", "Cookie"],
                "allow_passthrough_headers": ["authorization"],  # lowercase in config
            },
        )

        plugin = HeaderFilter(config)

        payload = ToolPreInvokePayload(
            name="test_tool",
            arguments={},
            headers=HttpHeaderPayload(
                root={
                    "Authorization": "Bearer token",  # Mixed case in request
                    "COOKIE": "session=xyz",  # Uppercase in request
                }
            ),
        )

        result = await plugin.tool_pre_invoke(payload, plugin_context)

        assert result.modified_payload is not None
        # Authorization passes through despite case difference
        assert "Authorization" in result.modified_payload.headers.root
        # Cookie is filtered
        assert "COOKIE" not in result.modified_payload.headers.root


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Made with Bob
