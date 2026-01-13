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
import asyncio
from enum import Enum
import hashlib
import json
import time
from urllib.parse import urlparse

# Third-Party
from pydantic import BaseModel, SecretStr

# First-Party
from mcpgateway.db import get_db
from mcpgateway.plugins.framework import (
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
        
        # Initialize encryption service if cache encryption is enabled
        self._encryption_service = None
        if self._sconfig.encrypt_cache:
            encryption_key = self._sconfig.cache_encryption_key
            if not encryption_key:
                # Use JWT secret as fallback
                from mcpgateway.config import settings
                encryption_key = settings.jwt_secret_key
            self._encryption_service = get_encryption_service(encryption_key)
            logger.info("Cache encryption enabled for vault plugin")

    def _get_cache_key(self, session_id: str, wrapped_token: str) -> str:
        """Generate cache key from session ID and wrapped token.

        Args:
            session_id: Session identifier from X-Vault-Session-ID header.
            wrapped_token: The wrapped token value.

        Returns:
            SHA-256 hash of session_id:wrapped_token.
        """
        return hashlib.sha256(f"{session_id}:{wrapped_token}".encode()).hexdigest()

    def _get_redis_key(self, cache_key: str) -> str:
        """Generate Redis key with namespace.

        Args:
            cache_key: The cache key hash.

        Returns:
            Redis key with mcpgw:vault:unwrapped: prefix.
        """
        return f"mcpgw:vault:unwrapped:{cache_key}"

    def _get_lock_key(self, cache_key: str) -> str:
        """Generate Redis lock key.

        Args:
            cache_key: The cache key hash.

        Returns:
            Redis lock key with mcpgw:vault:lock: prefix.
        """
        return f"mcpgw:vault:lock:{cache_key}"
    
    def _encrypt_token(self, token: str) -> str:
        """Encrypt a token for cache storage.

        Args:
            token: Plain text token to encrypt.

        Returns:
            Encrypted token (JSON bundle with encryption metadata).
        """
        if not self._encryption_service:
            return token
        
        try:
            return self._encryption_service.encrypt_secret(token)
        except Exception as e:
            logger.error(f"Failed to encrypt token: {e}")
            # Fall back to unencrypted
            return token
    
    def _decrypt_token(self, encrypted_token: str) -> str | None:
        """Decrypt a token from cache storage.

        Args:
            encrypted_token: Encrypted token (JSON bundle or plain text).

        Returns:
            Decrypted token, or None if decryption fails.
        """
        if not self._encryption_service:
            return encrypted_token
        
        # Check if token is encrypted
        if not self._encryption_service.is_encrypted(encrypted_token):
            return encrypted_token
        
        try:
            return self._encryption_service.decrypt_secret(encrypted_token)
        except Exception as e:
            logger.error(f"Failed to decrypt token: {e}")
            return None

    async def _get_or_unwrap_token(self, session_id: str, system_key: str, wrapped_token: str) -> str:
        """Get cached token or unwrap with distributed lock.

        Args:
            session_id: Session identifier for cache scoping.
            system_key: System identifier (e.g., "github.com").
            wrapped_token: The wrapped token to unwrap.

        Returns:
            Unwrapped token value.
        """
        cache_key = self._get_cache_key(session_id, wrapped_token)
        redis_key = self._get_redis_key(cache_key)
        lock_key = self._get_lock_key(cache_key)

        redis = await get_redis_client()
        if not redis:
            # No Redis - unwrap directly (single instance mode)
            logger.warning("Redis unavailable, unwrapping without cache")
            try:
                return await vault_proxy.async_unwrap_secret(token_name=system_key, vault_token=wrapped_token)
            except Exception as e:
                logger.error(f"Vault unwrap failed for system {system_key}: {e}")
                raise

        # Try to get cached token
        try:
            cached_encrypted = await redis.get(redis_key)
            if cached_encrypted:
                logger.info(f"Cache hit for session {session_id[:8]}...")
                cached = self._decrypt_token(cached_encrypted)
                if cached:
                    return cached
                else:
                    logger.warning(f"Failed to decrypt cached token for session {session_id[:8]}..., will unwrap")
                    # Fall through to unwrap
        except Exception as e:
            logger.error(f"Redis get error: {e}")
            # Fall through to unwrap

        # Cache miss - need to unwrap
        # Use distributed lock to ensure only one instance unwraps
        lock_ttl = 30  # Lock expires after 30 seconds
        lock_acquired = False

        try:
            # Try to acquire lock (SET NX with expiry)
            lock_acquired = await redis.set(lock_key, "1", nx=True, ex=lock_ttl)

            if lock_acquired:
                # We got the lock - check cache again (double-check pattern)
                cached_encrypted = await redis.get(redis_key)
                if cached_encrypted:
                    logger.info(f"Cache hit after lock for session {session_id[:8]}...")
                    cached = self._decrypt_token(cached_encrypted)
                    if cached:
                        return cached

                # Still not cached - unwrap the token
                logger.info(f"Unwrapping token for session {session_id[:8]}...")
                try:
                    unwrapped = await vault_proxy.async_unwrap_secret(token_name=system_key, vault_token=wrapped_token)
                except Exception as e:
                    logger.error(f"Vault unwrap failed for system {system_key}, session {session_id[:8]}...: {e}")
                    raise

                # Encrypt and cache the result
                encrypted_token = self._encrypt_token(unwrapped)
                await redis.setex(redis_key, int(self._sconfig.unwrap_cache_ttl_seconds), encrypted_token)
                logger.info(f"Cached unwrapped token for session {session_id[:8]}...")

                return unwrapped
            else:
                # Another instance is unwrapping - wait and retry
                logger.info("Waiting for another instance to unwrap token...")
                max_wait = 25  # Wait up to 25 seconds
                start_time = time.time()

                while time.time() - start_time < max_wait:
                    await asyncio.sleep(0.5)  # Poll every 500ms
                    cached_encrypted = await redis.get(redis_key)
                    if cached_encrypted:
                        logger.info("Got token from other instance")
                        cached = self._decrypt_token(cached_encrypted)
                        if cached:
                            return cached

                # Timeout - try to unwrap anyway
                logger.warning("Timeout waiting for other instance, unwrapping...")
                try:
                    return await vault_proxy.async_unwrap_secret(token_name=system_key, vault_token=wrapped_token)
                except Exception as e:
                    logger.error(f"Vault unwrap failed for system {system_key} after timeout: {e}")
                    raise

        except Exception as e:
            logger.error(f"Redis lock error: {e}, unwrapping without lock")
            # Fall back to direct unwrap
            try:
                return await vault_proxy.async_unwrap_secret(token_name=system_key, vault_token=wrapped_token)
            except Exception as unwrap_error:
                logger.error(f"Vault unwrap failed for system {system_key} after Redis error: {unwrap_error}")
                raise
        finally:
            # Release lock if we acquired it
            if lock_acquired:
                try:
                    await redis.delete(lock_key)
                except Exception as e:
                    logger.warning(f"Error releasing lock: {e}")

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
        logger.debug(f"Processing tool pre-invoke for tool {payload}  with context {context}")
        logger.debug(f"Gateway metadata {context.global_context.metadata['gateway']}")

        gateway_metadata = context.global_context.metadata["gateway"]

        system_key: str | None = None
        auth_header: str | None = None
        if self._sconfig.system_handling == SystemHandling.TAG:
            # Extract tags from dict format {"id": "...", "label": "..."}
            normalized_tags: list[str] = []
            for tag in gateway_metadata.tags:
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
                logger.info(f"Using vault system from GW tags: {system_key}")
            # Find auth header tag with the configured prefix (e.g., "AUTH_HEADER:X-GitHub-Token")
            auth_header_prefix = self._sconfig.auth_header_tag_prefix + ":"
            auth_header_tag = next((tag for tag in normalized_tags if tag.startswith(auth_header_prefix)), None)
            if auth_header_tag:
                auth_header = auth_header_tag.split(auth_header_prefix)[1]
                logger.info(f"Found AUTH_HEADER tag: {auth_header}")

        elif self._sconfig.system_handling == SystemHandling.OAUTH2_CONFIG:
            gen = get_db()
            db = next(gen)
            try:
                gateway_service = GatewayService()
                gw_id = context.global_context.server_id
                if gw_id:
                    gateway = await gateway_service.get_gateway(db, gw_id)
                    logger.info(f"Gateway used {gateway.oauth_config}")
                    if gateway.oauth_config and "token_url" in gateway.oauth_config:
                        token_url = gateway.oauth_config["token_url"]
                        parsed_url = urlparse(token_url)
                        system_key = parsed_url.hostname
                        logger.info(f"Using vault system from oauth_config: {system_key}")
            finally:
                gen.close()

        if not system_key:
            logger.warning("System cannot be determined from gateway metadata.")
            return ToolPreInvokeResult()

        modified = False
        headers: dict[str, str] = payload.headers.model_dump() if payload.headers else {}

        # Check if vault header exists
        if self._sconfig.vault_header_name not in headers:
            logger.debug(f"Vault header '{self._sconfig.vault_header_name}' not found in headers")
            return ToolPreInvokeResult()

        try:
            vault_tokens: dict[str, str] = json.loads(headers[self._sconfig.vault_header_name])
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse vault tokens from header: {e}")
            return ToolPreInvokeResult()

        vault_handling = self._sconfig.vault_handling

        # Try to find matching token in vault_tokens
        # First try exact match with system_key
        token_value: str | None = None
        token_key_used: str | None = None
        if system_key in vault_tokens:
            token_value = str(vault_tokens[system_key])
            token_key_used = str(system_key)
            logger.info(f"Found exact match for system key: {system_key}")
        else:
            # Try to find a key that starts with system_key (complex key format)
            for key in vault_tokens.keys():
                parsed_system, scope, token_type, token_name = self._parse_vault_token_key(key)
                if parsed_system == system_key:
                    token_value = vault_tokens[key]
                    token_key_used = key
                    logger.info(f"Found matching token with complex key: {key} (system: {parsed_system}, scope: {scope}, type: {token_type}, name: {token_name})")
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
                    return ToolPreInvokeResult()
                
                # Unwrap token with caching
                try:
                    token_value = await self._get_or_unwrap_token(
                        session_id=session_id,
                        system_key=parsed_system,
                        wrapped_token=token_value
                    )
                    logger.info(f"Using unwrapped token for system: {parsed_system}")
                except Exception as e:
                    logger.error(f"Failed to unwrap token for system {parsed_system}, session {session_id[:8]}...: {e}")
                    # Return empty result - cannot proceed without valid token
                    return ToolPreInvokeResult()
            
            # Determine how to set the token based on token_type and AUTH_HEADER tag
            if token_type == "PAT":
                # Handle Personal Access Token
                logger.info(f"Processing PAT token for system: {parsed_system}")
                # Check if AUTH_HEADER tag is defined
                if auth_header:
                    logger.info(f"Using AUTH_HEADER tag for {parsed_system}: header={auth_header}")
                    headers[auth_header] = str(token_value)
                    modified = True
                else:
                    # No AUTH_HEADER tag, use default Bearer token
                    logger.info(f"No AUTH_HEADER tag found for {parsed_system}, using Bearer token")
                    headers["Authorization"] = f"Bearer {token_value}"
                    modified = True
            elif token_type == "OAUTH2" or token_type is None:
                # Handle OAuth2 token or default behavior (when token_type is missing)
                logger.info(f"Set Bearer token for system: {parsed_system}")
                headers["Authorization"] = f"Bearer {token_value}"
                modified = True
            else:
                # Unknown token type, use default Bearer token
                logger.warning(f"Unknown token type '{token_type}', using default Bearer token")
                headers["Authorization"] = f"Bearer {token_value}"
                modified = True

            # Remove vault header after processing
            if modified and self._sconfig.vault_header_name in headers:
                del headers[self._sconfig.vault_header_name]

            payload.headers = HttpHeaderPayload(root=headers)

        if modified:
            logger.info(f"Modified tool '{payload.name}' to add auth header")
            return ToolPreInvokeResult(modified_payload=payload)

        return ToolPreInvokeResult()

    async def shutdown(self) -> None:
        """Shutdown the plugin gracefully.

        Returns:
            None.
        """
        return None
