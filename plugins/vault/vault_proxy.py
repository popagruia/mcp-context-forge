# Standard
import asyncio
import json
import logging
import os
from typing import Any, Dict, List

# Third-Party
import aiohttp
import requests

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class TokenNotFoundError(Exception):
    """Exception raised when a token is not found."""

    pass


async def async_unwrap_secret(token_name: str, vault_token: str | None = None) -> str:
    logger.info(f"Unwrapping token {token_name}")
    try:
        base_url = os.getenv("VAULT_PROXY_URL")
        x_api_key = os.getenv("VAULT_API_KEY")

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
                    logger.error(f"Failed to unwrap token {token_name}: {str(e)}")
                    raise TokenNotFoundError(f"Token '{token_name}' not found")

                if not json_data or ("secretValue" not in json_data):
                    raise TokenNotFoundError(f"Token '{token_name}' not found")

                data = json_data["secretValue"]
                return data

    except aiohttp.ClientError as e:
        logger.error(f"Failed to fetch token {token_name} {str(e)}")
        raise TokenNotFoundError(f"Failed to fetch token {token_name}: {str(e)}")
