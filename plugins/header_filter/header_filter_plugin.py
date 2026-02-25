# -*- coding: utf-8 -*-
"""Location: ./plugins/header_filter/header_filter_plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Adrian Popa

Header Filter Plugin.

Filters sensitive headers before sending requests to MCP endpoints.
Prevents leakage of authentication tokens, cookies, and other sensitive data.

Hook: tool_pre_invoke, resource_pre_fetch, prompt_prehook, agent_pre_invoke
"""

# Standard
from typing import Set

# Third-Party
from pydantic import BaseModel, Field

# First-Party
from mcpgateway.plugins.framework import (
    AgentPreInvokePayload,
    AgentPreInvokeResult,
    HttpHeaderPayload,
    Plugin,
    PluginConfig,
    PluginContext,
    PromptPrehookPayload,
    PromptPrehookResult,
    ResourcePreFetchPayload,
    ResourcePreFetchResult,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from mcpgateway.services.logging_service import LoggingService

# Initialize logging service
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class HeaderFilterConfig(BaseModel):
    """Configuration for header filter plugin.

    Attributes:
        filter_headers: Set of header names to filter (case-insensitive).
        log_filtered_headers: Whether to log which headers were filtered.
        allow_passthrough_headers: Set of headers to always allow through (overrides filter_headers).
    """

    filter_headers: Set[str] = Field(
        default_factory=lambda: {
            "Authorization",
            "Cookie",
            "X-Vault-Tokens",
            "X-API-Key",
            "X-Auth-Token",
            "Proxy-Authorization",
            "WWW-Authenticate",
            "Set-Cookie",
        }
    )
    log_filtered_headers: bool = True
    allow_passthrough_headers: Set[str] = Field(default_factory=set)


class HeaderFilter(Plugin):
    """Header filter plugin that removes sensitive headers before sending to MCP endpoints.

    This plugin prevents sensitive authentication and authorization headers from being
    leaked to MCP servers. It runs on all pre-invoke hooks (tool, resource, prompt, agent)
    to ensure consistent header filtering across all MCP operations.

    Security considerations:
    - Headers are filtered case-insensitively
    - Passthrough headers take precedence over filter list
    - Always removes filtered headers even if plugin encounters errors
    """

    def __init__(self, config: PluginConfig):
        """Initialize the header filter plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        try:
            self._sconfig = HeaderFilterConfig.model_validate(self._config.config or {})
        except Exception as e:
            logger.warning(f"Failed to parse header filter config, using defaults: {e}")
            self._sconfig = HeaderFilterConfig()

        # Normalize header names to lowercase for case-insensitive comparison
        self._filter_headers_lower = {h.lower() for h in self._sconfig.filter_headers}
        self._passthrough_headers_lower = {h.lower() for h in self._sconfig.allow_passthrough_headers}

        logger.info(f"Header filter initialized: filtering {len(self._filter_headers_lower)} headers, " f"allowing {len(self._passthrough_headers_lower)} passthrough headers")

    def _filter_headers(self, headers: dict[str, str], context_name: str) -> tuple[dict[str, str], list[str]]:
        """Filter sensitive headers from the header dictionary.

        Args:
            headers: Dictionary of headers to filter.
            context_name: Context name for logging (e.g., "tool:my_tool").

        Returns:
            Tuple of (filtered_headers, list_of_filtered_header_names).
        """
        filtered_headers = {}
        removed_headers = []

        for header_name, header_value in headers.items():
            header_lower = header_name.lower()

            # Check if header is in passthrough list (takes precedence)
            if header_lower in self._passthrough_headers_lower:
                filtered_headers[header_name] = header_value
                continue

            # Check if header should be filtered
            if header_lower in self._filter_headers_lower:
                removed_headers.append(header_name)
                if self._sconfig.log_filtered_headers:
                    logger.debug(f"Filtered header '{header_name}' from {context_name}")
                continue

            # Header is not filtered, keep it
            filtered_headers[header_name] = header_value

        return filtered_headers, removed_headers

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Filter headers before tool invocation.

        Args:
            payload: The tool payload containing headers.
            context: Plugin execution context.

        Returns:
            Result with filtered headers.
        """
        if not payload.headers:
            return ToolPreInvokeResult()

        headers = payload.headers.model_dump()
        context_name = f"tool:{payload.name}"

        filtered_headers, removed = self._filter_headers(headers, context_name)

        if removed:
            if self._sconfig.log_filtered_headers:
                logger.info(f"Filtered {len(removed)} header(s) from {context_name}: {', '.join(removed)}")
            payload.headers = HttpHeaderPayload(root=filtered_headers)
            return ToolPreInvokeResult(modified_payload=payload)

        return ToolPreInvokeResult()

    async def resource_pre_fetch(self, payload: ResourcePreFetchPayload, context: PluginContext) -> ResourcePreFetchResult:  # pylint: disable=unused-argument
        """Filter headers before resource fetch.

        Args:
            payload: The resource payload containing headers.
            context: Plugin execution context.

        Returns:
            Result with filtered headers.
        """
        if not payload.headers:
            return ResourcePreFetchResult()

        headers = payload.headers.model_dump()
        context_name = f"resource:{payload.uri}"

        filtered_headers, removed = self._filter_headers(headers, context_name)

        if removed:
            if self._sconfig.log_filtered_headers:
                logger.info(f"Filtered {len(removed)} header(s) from {context_name}: {', '.join(removed)}")
            payload.headers = HttpHeaderPayload(root=filtered_headers)
            return ResourcePreFetchResult(modified_payload=payload)

        return ResourcePreFetchResult()

    async def prompt_prehook(self, payload: PromptPrehookPayload, context: PluginContext) -> PromptPrehookResult:  # pylint: disable=unused-argument
        """Filter headers before prompt execution.

        Args:
            payload: The prompt payload containing headers.
            context: Plugin execution context.

        Returns:
            Result with filtered headers.
        """
        if not payload.headers:
            return PromptPrehookResult()

        headers = payload.headers.model_dump()
        context_name = f"prompt:{payload.name}"

        filtered_headers, removed = self._filter_headers(headers, context_name)

        if removed:
            if self._sconfig.log_filtered_headers:
                logger.info(f"Filtered {len(removed)} header(s) from {context_name}: {', '.join(removed)}")
            payload.headers = HttpHeaderPayload(root=filtered_headers)
            return PromptPrehookResult(modified_payload=payload)

        return PromptPrehookResult()

    async def agent_pre_invoke(self, payload: AgentPreInvokePayload, context: PluginContext) -> AgentPreInvokeResult:  # pylint: disable=unused-argument
        """Filter headers before agent invocation.

        Args:
            payload: The agent payload containing headers.
            context: Plugin execution context.

        Returns:
            Result with filtered headers.
        """
        if not payload.headers:
            return AgentPreInvokeResult()

        headers = payload.headers.model_dump()
        context_name = f"agent:{payload.name}"

        filtered_headers, removed = self._filter_headers(headers, context_name)

        if removed:
            if self._sconfig.log_filtered_headers:
                logger.info(f"Filtered {len(removed)} header(s) from {context_name}: {', '.join(removed)}")
            payload.headers = HttpHeaderPayload(root=filtered_headers)
            return AgentPreInvokeResult(modified_payload=payload)

        return AgentPreInvokeResult()

    async def shutdown(self) -> None:
        """Shutdown the plugin gracefully.

        Returns:
            None.
        """
        logger.info("Header filter plugin shutting down")
        return None


# Made with Bob
