# -*- coding: utf-8 -*-
"""Location: ./plugins/vault/vault_proxy.py
Copyright 2025
SPDX-License-Identifier: Apache-2.0

Vault Proxy Client for token unwrapping.

This module provides functionality to unwrap wrapped tokens from a vault proxy service.
Wrapped tokens are single-use tokens that must be unwrapped to retrieve the actual secret.
"""

# Standard
import asyncio
import json
import os
from typing import Any, Dict, List, Tuple

# Third-Party
import aiohttp

# First-Party
from mcpgateway.services.logging_service import LoggingService

# Initialize logging
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)


class TokenNotFoundError(Exception):
    """Exception raised when a token cannot be found or unwrapped."""
    pass


class MultipleTokenFetchErrors(Exception):
    """Exception raised when multiple tokens fail to unwrap."""
    
    def __init__(self, errors: Dict[str, str]):
        """Initialize with dictionary of path -> error message."""
        self.errors = errors
        super().__init__(f"Failed to fetch {len(errors)} tokens: {errors}")


async def async_unwrap_secret(token_name: str, vault_token: str | None = None) -> Dict[str, Any]:
    """Unwrap a wrapped token from vault proxy service.
    
    This function calls the vault proxy API to unwrap a single-use wrapped token
    and retrieve the actual secret value.
    
    Args:
        token_name: System identifier or token name (e.g., "github.com")
        vault_token: The wrapped token to unwrap (optional, can be in header)
        
    Returns:
        Dict with keys:
            - "key": The token name
            - "value": The unwrapped secret value
            
    Raises:
        EnvironmentError: If VAULT_PROXY_URL is not set
        TokenNotFoundError: If token cannot be unwrapped or not found
        aiohttp.ClientError: If HTTP request fails
        
    Example:
        >>> result = await async_unwrap_secret("github.com", "hvs.wrapped_token")
        >>> print(result)
        {"key": "github.com", "value": "ghp_actual_token_xyz"}
    """
    logger.info(f"Unwrapping token {token_name}")
    try:
        base_url = os.getenv('VAULT_PROXY_URL')
        x_api_key = os.getenv('VAULT_API_KEY')
        
        if not base_url:
            raise EnvironmentError("VAULT_PROXY_URL environment variable is not set")
        
        url = f"{base_url}/vault-proxy/api/secret/v1/unwrap"
        logger.info(f"Loading token from {url}")
    
        headers: Dict[str, str] = {}
        if vault_token:
            headers["X-Vault-Token"] = vault_token
        if x_api_key:
            headers["X-API-Key"] = x_api_key
        
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers) as response:
                response.raise_for_status()
                
                data = await response.text()
                try:
                    json_data = json.loads(data)
                except Exception as e:
                    logger.error(f"Failed to parse JSON response for token {token_name}: {str(e)}")
                    raise TokenNotFoundError(f"Token '{token_name}' not found - invalid JSON response")      
                
                if not json_data or ("secretValue" not in json_data):
                    logger.error(f"Token {token_name} not found in response: {json_data}")
                    raise TokenNotFoundError(f"Token '{token_name}' not found - missing secretValue")
                    
                logger.info(f"Successfully unwrapped token {token_name}")
                return {
                    "key": token_name,
                    "value": json_data["secretValue"]
                } 
    except aiohttp.ClientError as e:
        logger.error(f"Failed to fetch token at path {token_name}: {str(e)}")
        raise TokenNotFoundError(f"Failed to fetch token at path: {str(e)}")
    except EnvironmentError:
        # Re-raise environment errors as-is
        raise
    except TokenNotFoundError:
        # Re-raise token not found errors as-is
        raise
    except Exception as e:
        logger.error(f"Unexpected error unwrapping token {token_name}: {str(e)}")
        raise TokenNotFoundError(f"Unexpected error unwrapping token: {str(e)}")


async def async_fetch_unwrapped_tokens(tokens: Dict[str, str]) -> Dict[str, Any]:
    """Unwrap multiple wrapped tokens concurrently.
    
    This function unwraps multiple tokens in parallel using asyncio.gather,
    improving performance when multiple tokens need to be unwrapped.
    
    Args:
        tokens: Dictionary mapping token names to wrapped token values
                Example: {"github.com": "hvs.wrapped1", "gitlab.com": "hvs.wrapped2"}
        
    Returns:
        Dictionary mapping token names to unwrapped secret values
        Example: {"github.com": "ghp_token1", "gitlab.com": "glpat_token2"}
        
    Raises:
        MultipleTokenFetchErrors: If any tokens fail to unwrap, with details of all failures
        
    Example:
        >>> tokens = {"github.com": "hvs.wrapped1", "gitlab.com": "hvs.wrapped2"}
        >>> result = await async_fetch_unwrapped_tokens(tokens)
        >>> print(result)
        {"github.com": "ghp_token1", "gitlab.com": "glpat_token2"}
    """
    logger.info(f"Unwrapping {len(tokens)} tokens concurrently")
    coroutines: List[Any] = []
    
    # Prepare a list of coroutines for each token
    for name, wrapped_token in tokens.items():
        coroutines.append(async_unwrap_secret(name, wrapped_token))
    
    # Gather results with exceptions (don't fail fast)
    results: List[Any] = await asyncio.gather(*coroutines, return_exceptions=True)
    
    final_results: Dict[str, Any] = {}
    errors: List[Tuple[str, str]] = []
    
    # Pair each result with its corresponding path from the original tokens dictionary
    for (path, coroutine_result) in zip(tokens.keys(), results):
        if isinstance(coroutine_result, dict):
            token_value = coroutine_result.get("value", {})
            final_results[path] = token_value
            logger.debug(f"Successfully unwrapped token for {path}")
        else:
            # If there's an error, store it
            error_msg = str(coroutine_result)
            errors.append((path, error_msg))
            logger.error(f"Failed to unwrap token for {path}: {error_msg}")
    
    # Check if there are any errors
    if len(errors) > 0:
        error_dict: Dict[str, str] = {path: error for (path, error) in errors}
        logger.error(f"Failed to unwrap {len(errors)} out of {len(tokens)} tokens")
        raise MultipleTokenFetchErrors(error_dict)
    else:
        logger.info(f"Successfully unwrapped all {len(tokens)} tokens")
        return final_results

# Made with Bob
