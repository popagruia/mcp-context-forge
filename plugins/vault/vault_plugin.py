# -*- coding: utf-8 -*-
"""Location: ./plugins/vault/vault_plugin.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0
Authors: Mihai Criveti

Vault Plugin.

Generates bearer tokens from vault-saved tokens based on OAUTH2 config protecting a tool.

Hook: tool_pre_invoke
"""

# Standard
from enum import Enum
from urllib.parse import urlparse

# Third-Party
import orjson
from pydantic import BaseModel, SecretStr

# First-Party
from mcpgateway.db import get_db
from mcpgateway.plugins.framework import (
    get_attr,
    HttpHeaderPayload,
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)
from mcpgateway.services.encryption_service import get_encryption_service
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.services.logging_service import LoggingService
from mcpgateway.utils.redis_client import get_redis_client

# Local
from . import vault_proxy
from .vault_cache import VaultCacheManager

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class VaultHandling(Enum):
    """Vault token handling modes.

    Attributes:
        RAW: Use raw token from vault.
        UNWRAP: Unwrap token from vault proxy (single-use tokens).
    """

    RAW = "raw"
    UNWRAP = "unwrap"


class SystemHandling(Enum):
    """System identification handling modes.

    Attributes:
        TAG: Identify system from gateway tags.
        OAUTH2_CONFIG: Identify system from OAuth2 config.
    """

    TAG = "tag"
    OAUTH2_CONFIG = "oauth2_config"


class VaultConfig(BaseModel):
    """Configuration for vault plugin.

    Attributes:
        system_tag_prefix: Prefix for system tags.
        vault_header_name: HTTP header name for vault tokens.
        vault_session_header: HTTP header name for session ID (used with UNWRAP mode).
        vault_handling: Vault token handling mode.
        system_handling: System identification mode.
        auth_header_tag_prefix: Prefix for auth header tags (e.g., "AUTH_HEADER").
        unwrap_cache_ttl_seconds: TTL for unwrapped token cache in seconds.
        encrypt_cache: Enable encryption for cached tokens.
        cache_encryption_key: Encryption key for cache (uses JWT secret if not provided).
    """

    system_tag_prefix: str = "system"
    vault_header_name: str = "X-Vault-Tokens"
    vault_session_header: str = "X-Vault-Session-ID"
    vault_handling: VaultHandling = VaultHandling.RAW
    system_handling: SystemHandling = SystemHandling.TAG
    auth_header_tag_prefix: str = "AUTH_HEADER"
    unwrap_cache_ttl_seconds: float = 600.0
    encrypt_cache: bool = True
    cache_encryption_key: SecretStr | None = None


class Vault(Plugin):
    """Vault plugin that based on OAUTH2 config that protects a tool will generate bearer token based on a vault saved token"""

    def __init__(self, config: PluginConfig):
        """Initialize the vault plugin.

        Args:
            config: Plugin configuration.
        """
        super().__init__(config)
        # load config with pydantic model for convenience
        try:
            self._sconfig = VaultConfig.model_validate(self._config.config or {})
        except Exception:
            self._sconfig = VaultConfig()
        
        # Initialize encryption service and cache manager if cache encryption is enabled
        self._cache_manager: VaultCacheManager | None = None
        if self._sconfig.encrypt_cache:
            encryption_key = self._sconfig.cache_encryption_key
            if not encryption_key:
                # Use JWT secret as fallback
                from mcpgateway.config import settings
                encryption_key = settings.jwt_secret_key
            encryption_service = get_encryption_service(encryption_key)
            self._cache_manager = VaultCacheManager(
                encryption_service=encryption_service,
                ttl_seconds=self._sconfig.unwrap_cache_ttl_seconds,
            )
            logger.info("Cache encryption enabled for vault plugin")
        else:
            # Cache manager without encryption
            self._cache_manager = VaultCacheManager(
                encryption_service=None,
                ttl_seconds=self._sconfig.unwrap_cache_ttl_seconds,
            )

    def _parse_vault_token_key(self, key: str) -> tuple[str, str | None, str | None, str | None]:
        """Parse vault token key in format: system[:scope][:token_type][:token_name].

        Args:
            key: Token key to parse (e.g., "github.com:USER:OAUTH2:TOKEN" or "github.com").

        Returns:
            Tuple of (system, scope, token_type, token_name). Missing parts are None.
        """
        parts = key.split(":")
        system = parts[0] if len(parts) > 0 else key
        scope = parts[1] if len(parts) > 1 else None
        token_type = parts[2] if len(parts) > 2 else None
        token_name = parts[3] if len(parts) > 3 else None
        return system, scope, token_type, token_name

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Generate bearer tokens from vault-saved tokens before tool invocation.

        Args:
            payload: The tool payload containing arguments.
            context: Plugin execution context.

        Returns:
            Result with potentially modified headers containing bearer token.
        """
        logger.debug("Processing tool pre-invoke for tool %s", payload.name)
        logger.debug("Gateway metadata for server %s", context.global_context.server_id)

        gateway_metadata = context.global_context.metadata.get("gateway")

        system_key: str | None = None
        auth_header: str | None = None
        if self._sconfig.system_handling == SystemHandling.TAG:
            # Extract tags from dict format {"id": "...", "label": "..."}
            normalized_tags: list[str] = []
            gateway_tags = get_attr(gateway_metadata, "tags", [])
            for tag in gateway_tags if gateway_tags else []:
                if isinstance(tag, dict):
                    # Use 'label' field (the actual tag value)
                    tag_value = str(tag.get("label", ""))
                    if tag_value:
                        normalized_tags.append(tag_value)
                elif hasattr(tag, "label"):
                    normalized_tags.append(str(getattr(tag, "label")))
            # Find system tag with the configured prefix
            system_prefix = self._sconfig.system_tag_prefix + ":"
            system_tag = next((tag for tag in normalized_tags if tag.startswith(system_prefix)), None)
            if system_tag:
                system_key = system_tag.split(system_prefix)[1]
                logger.debug("Using vault system from GW tags: %s", system_key)
            # Find auth header tag with the configured prefix (e.g., "AUTH_HEADER:X-GitHub-Token")
            auth_header_prefix = self._sconfig.auth_header_tag_prefix + ":"
            auth_header_tag = next((tag for tag in normalized_tags if tag.startswith(auth_header_prefix)), None)
            if auth_header_tag:
                auth_header = auth_header_tag.split(auth_header_prefix)[1]
                logger.debug("Found AUTH_HEADER tag: %s", auth_header)

        elif self._sconfig.system_handling == SystemHandling.OAUTH2_CONFIG:
            gen = get_db()
            db = next(gen)
            try:
                gateway_service = GatewayService()
                gw_id = context.global_context.server_id
                if gw_id:
                    gateway = await gateway_service.get_gateway(db, gw_id)
                    logger.debug("Gateway oauth_config resolved")
                    if gateway.oauth_config and "token_url" in gateway.oauth_config:
                        token_url = gateway.oauth_config["token_url"]
                        parsed_url = urlparse(token_url)
                        system_key = parsed_url.hostname
                        logger.debug("Using vault system from oauth_config: %s", system_key)
            finally:
                gen.close()

        if not system_key:
            logger.warning("System cannot be determined from gateway metadata.")
            # SECURITY: Strip vault header even when system cannot be determined
            if payload.headers:
                safe_headers = payload.headers.model_dump()
                if self._sconfig.vault_header_name in safe_headers:
                    del safe_headers[self._sconfig.vault_header_name]
                    payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=safe_headers)})
                    return ToolPreInvokeResult(modified_payload=payload)
            return ToolPreInvokeResult()

        modified = False
        headers: dict[str, str] = payload.headers.model_dump() if payload.headers else {}

        # Check if vault header exists
        if self._sconfig.vault_header_name not in headers:
            logger.debug("Vault header '%s' not found in headers", self._sconfig.vault_header_name)
            return ToolPreInvokeResult()

        try:
            vault_tokens = orjson.loads(headers[self._sconfig.vault_header_name])
        except (orjson.JSONDecodeError, TypeError) as e:
            logger.error("Failed to parse vault tokens from header: %s", e)
            # SECURITY: Always remove vault header even on parse error
            del headers[self._sconfig.vault_header_name]
            payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=headers)})
            return ToolPreInvokeResult(modified_payload=payload)

        # SECURITY: Always remove vault header immediately after successful parsing
        # This header should NEVER be sent to the MCP server
        del headers[self._sconfig.vault_header_name]

        if not isinstance(vault_tokens, dict):
            logger.error("Vault tokens header is not a JSON object: %s", type(vault_tokens).__name__)
            payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=headers)})
            return ToolPreInvokeResult(modified_payload=payload)
        logger.debug("Removed vault header '%s' from headers", self._sconfig.vault_header_name)

        vault_handling = self._sconfig.vault_handling

        # Try to find matching token in vault_tokens
        # First try exact match with system_key
        token_value: str | None = None
        token_key_used: str | None = None
        if system_key in vault_tokens:
            token_value = str(vault_tokens[system_key])
            token_key_used = str(system_key)
            logger.debug("Found exact match for system key: %s", system_key)
        else:
            # Try to find a key that starts with system_key (complex key format)
            for key in vault_tokens.keys():
                parsed_system, scope, token_type, token_name = self._parse_vault_token_key(key)
                if parsed_system == system_key:
                    token_value = vault_tokens[key]
                    token_key_used = key
                    logger.debug("Found matching token with complex key for system: %s", parsed_system)
                    break

        if token_value and token_key_used:
            # Parse the token key to determine handling
            parsed_system, scope, token_type, token_name = self._parse_vault_token_key(token_key_used)
            
            # Unwrap token first if UNWRAP mode is enabled (applies to all token types)
            if vault_handling == VaultHandling.UNWRAP:
                # Get session ID from header
                session_id = headers.get(self._sconfig.vault_session_header)
                if not session_id:
                    logger.error(f"UNWRAP mode requires {self._sconfig.vault_session_header} header")
                    payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=headers)})
                    return ToolPreInvokeResult(modified_payload=payload)
                
                # Unwrap token with caching
                if self._cache_manager:
                    try:
                        redis_client = await get_redis_client()
                        
                        async def unwrap_fn(system_key: str, wrapped_token: str) -> str:
                            """Wrapper function for vault_proxy.async_unwrap_secret"""
                            result = await vault_proxy.async_unwrap_secret(token_name=system_key, vault_token=wrapped_token)
                            return result["value"]
                        
                        token_value = await self._cache_manager.get_with_lock(
                            redis_client=redis_client,
                            session_id=session_id,
                            system_key=parsed_system,
                            wrapped_token=token_value,
                            unwrap_fn=unwrap_fn,
                        )
                        logger.info(f"Using unwrapped token for system: {parsed_system}")
                    except Exception as e:
                        logger.error(f"Failed to unwrap token for system {parsed_system}, session {session_id[:8]}...: {e}")
                        # Return modified payload with vault header removed
                        payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=headers)})
                        return ToolPreInvokeResult(modified_payload=payload)
                else:
                    logger.error("Cache manager not initialized for UNWRAP mode")
                    payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=headers)})
                    return ToolPreInvokeResult(modified_payload=payload)
            
            # Determine how to handle the token based on token_type and AUTH_HEADER tag
            if token_type == "PAT":
                # Handle Personal Access Token
                logger.debug("Processing PAT token for system: %s", parsed_system)
                # Check if AUTH_HEADER tag is defined
                if auth_header:
                    logger.debug("Using AUTH_HEADER tag for %s: header=%s", parsed_system, auth_header)
                    headers[auth_header] = str(token_value)
                    modified = True
                else:
                    # No AUTH_HEADER tag, use default Bearer token
                    logger.debug("No AUTH_HEADER tag found for %s, using Bearer token", parsed_system)
                    headers["Authorization"] = f"Bearer {token_value}"
                    modified = True
            elif token_type == "OAUTH2" or token_type is None:
                # Handle OAuth2 token or default behavior (when token_type is missing)
                logger.debug("Set Bearer token for system: %s", parsed_system)
                headers["Authorization"] = f"Bearer {token_value}"
                modified = True
            else:
                # Unknown token type, use default Bearer token
                logger.warning("Unknown token type '%s', using default Bearer token", token_type)
                headers["Authorization"] = f"Bearer {token_value}"
                modified = True

        if modified:
            logger.debug("Modified tool '%s' to add auth header", payload.name)
        elif not token_value:
            # Even if we didn't modify headers (no token match), we still removed the vault header
            logger.warning("Vault tokens provided but no match found for system '%s' - possible misconfiguration", system_key)

        # Always return modified payload since the vault header was stripped
        payload = payload.model_copy(update={"headers": HttpHeaderPayload(root=headers)})
        return ToolPreInvokeResult(modified_payload=payload)

    async def shutdown(self) -> None:
        """Shutdown the plugin gracefully.

        Returns:
            None.
        """
        return None
