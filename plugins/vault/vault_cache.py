# -*- coding: utf-8 -*-
"""Location: ./plugins/vault/vault_cache.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Vault Cache Manager for token unwrapping.

This module provides Redis-based caching with encryption and distributed locking
for unwrapped vault tokens. It ensures that single-use wrapped tokens are only
unwrapped once and cached for subsequent requests within a session.
"""

# Standard
import asyncio
import hashlib
import time
from typing import Callable, Awaitable

# First-Party
from mcpgateway.services.encryption_service import EncryptionService
from mcpgateway.services.logging_service import LoggingService

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class VaultCacheManager:
    """Manages Redis-based caching for unwrapped vault tokens.
    
    Features:
    - Session-scoped caching (tokens are scoped to user sessions)
    - Encryption at rest using Fernet + Argon2id
    - Distributed locking to prevent duplicate unwrapping
    - Configurable TTL for cache entries
    """

    def __init__(
        self,
        encryption_service: EncryptionService | None,
        ttl_seconds: float = 600.0,
    ):
        """Initialize the cache manager.
        
        Args:
            encryption_service: Service for encrypting/decrypting tokens (optional)
            ttl_seconds: Time-to-live for cached tokens in seconds
        """
        self._encryption_service = encryption_service
        self._ttl_seconds = ttl_seconds

    def get_cache_key(self, session_id: str, wrapped_token: str) -> str:
        """Generate cache key from session ID and wrapped token.
        
        Args:
            session_id: Session identifier from X-Vault-Session-ID header
            wrapped_token: The wrapped token value
            
        Returns:
            SHA-256 hash of session_id:wrapped_token
        """
        return hashlib.sha256(f"{session_id}:{wrapped_token}".encode()).hexdigest()

    def get_redis_key(self, cache_key: str) -> str:
        """Generate Redis key with namespace.
        
        Args:
            cache_key: The cache key hash
            
        Returns:
            Redis key with mcpgw:vault:unwrapped: prefix
        """
        return f"mcpgw:vault:unwrapped:{cache_key}"

    def get_lock_key(self, cache_key: str) -> str:
        """Generate Redis lock key.
        
        Args:
            cache_key: The cache key hash
            
        Returns:
            Redis lock key with mcpgw:vault:lock: prefix
        """
        return f"mcpgw:vault:lock:{cache_key}"

    def encrypt_token(self, token: str) -> str:
        """Encrypt a token for cache storage.
        
        Args:
            token: Plain text token to encrypt
            
        Returns:
            Encrypted token (JSON bundle with encryption metadata)
        """
        if not self._encryption_service:
            return token
        
        try:
            return self._encryption_service.encrypt_secret(token)
        except Exception as e:
            logger.error(f"Failed to encrypt token: {e}")
            # Fall back to unencrypted
            return token

    def decrypt_token(self, encrypted_token: str) -> str | None:
        """Decrypt a token from cache storage.
        
        Args:
            encrypted_token: Encrypted token (JSON bundle or plain text)
            
        Returns:
            Decrypted token, or None if decryption fails
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

    async def get_with_lock(
        self,
        redis_client,
        session_id: str,
        system_key: str,
        wrapped_token: str,
        unwrap_fn: Callable[[str, str], Awaitable[str]],
    ) -> str:
        """Get cached token or unwrap with distributed lock.
        
        This method implements a distributed locking pattern to ensure that
        only one instance unwraps a token at a time. Other instances will
        wait for the first one to complete and then retrieve from cache.
        
        Args:
            redis_client: Redis client instance (or None for single-instance mode)
            session_id: Session identifier for cache scoping
            system_key: System identifier (e.g., "github.com")
            wrapped_token: The wrapped token to unwrap
            unwrap_fn: Async function to unwrap token (token_name, vault_token) -> unwrapped_token
            
        Returns:
            Unwrapped token value
            
        Raises:
            Exception: If unwrapping fails
        """
        cache_key = self.get_cache_key(session_id, wrapped_token)
        redis_key = self.get_redis_key(cache_key)
        lock_key = self.get_lock_key(cache_key)

        if not redis_client:
            # No Redis - unwrap directly (single instance mode)
            logger.warning("Redis unavailable, unwrapping without cache")
            try:
                return await unwrap_fn(system_key, wrapped_token)
            except Exception as e:
                logger.error(f"Vault unwrap failed for system {system_key}: {e}")
                raise

        # Try to get cached token
        try:
            cached_encrypted = await redis_client.get(redis_key)
            if cached_encrypted:
                logger.info(f"Cache hit for session {session_id[:8]}...")
                cached = self.decrypt_token(cached_encrypted)
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
            lock_acquired = await redis_client.set(lock_key, "1", nx=True, ex=lock_ttl)

            if lock_acquired:
                # We got the lock - check cache again (double-check pattern)
                cached_encrypted = await redis_client.get(redis_key)
                if cached_encrypted:
                    logger.info(f"Cache hit after lock for session {session_id[:8]}...")
                    cached = self.decrypt_token(cached_encrypted)
                    if cached:
                        return cached

                # Still not cached - unwrap the token
                logger.info(f"Unwrapping token for session {session_id[:8]}...")
                try:
                    unwrapped = await unwrap_fn(system_key, wrapped_token)
                except Exception as e:
                    logger.error(f"Vault unwrap failed for system {system_key}, session {session_id[:8]}...: {e}")
                    raise

                # Encrypt and cache the result
                encrypted_token = self.encrypt_token(unwrapped)
                await redis_client.setex(redis_key, int(self._ttl_seconds), encrypted_token)
                logger.info(f"Cached unwrapped token for session {session_id[:8]}...")

                return unwrapped
            else:
                # Another instance is unwrapping - wait and retry
                logger.info("Waiting for another instance to unwrap token...")
                max_wait = 25  # Wait up to 25 seconds
                start_time = time.time()

                while time.time() - start_time < max_wait:
                    await asyncio.sleep(0.5)  # Poll every 500ms
                    cached_encrypted = await redis_client.get(redis_key)
                    if cached_encrypted:
                        logger.info("Got token from other instance")
                        cached = self.decrypt_token(cached_encrypted)
                        if cached:
                            return cached

                # Timeout - try to unwrap anyway
                logger.warning("Timeout waiting for other instance, unwrapping...")
                try:
                    return await unwrap_fn(system_key, wrapped_token)
                except Exception as e:
                    logger.error(f"Vault unwrap failed for system {system_key} after timeout: {e}")
                    raise

        except Exception as e:
            logger.error(f"Redis lock error: {e}, unwrapping without lock")
            # Fall back to direct unwrap
            try:
                return await unwrap_fn(system_key, wrapped_token)
            except Exception as unwrap_error:
                logger.error(f"Vault unwrap failed for system {system_key} after Redis error: {unwrap_error}")
                raise
        finally:
            # Release lock if we acquired it
            if lock_acquired:
                try:
                    await redis_client.delete(lock_key)
                except Exception as e:
                    logger.warning(f"Error releasing lock: {e}")

# Made with Bob
