# -*- coding: utf-8 -*-

from pydantic import BaseModel
from enum import Enum


from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

from mcpgateway.plugins.framework.models import HttpHeaderPayload
from mcpgateway.services.logging_service import LoggingService
from plugins.vault.vault_proxy import async_unwrap_secret

from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.db import get_db
from urllib.parse import urlparse

import json
from mcpgateway.services.gateway_service import GatewayService

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

class VaultHandling(Enum):
    RAW = "raw"
    UNWRAP = "unwrap"

class SystemHandling(Enum):
    TAG = "tag"
    OAUTH2_CONFIG = "oauth2_config"

class VaultConfig(BaseModel):
    system_tag_prefix: str = "system"
    vault_header_name: str = "X-Vault-Tokens"
    vault_handling: VaultHandling = VaultHandling.UNWRAP
    system_handling: SystemHandling = SystemHandling.TAG


class Vault(Plugin):
    """Vault plugin that based on OAUTH2 config that protects a tool will generate bearer token based on a vault saved token"""

    def __init__(self, config: PluginConfig):
        super().__init__(config)
        # load config with pydantic model for convenience
        try:
            self._sconfig = VaultConfig.model_validate(self._config.config or {})
        except Exception:
            self._sconfig = VaultConfig()

    async def tool_pre_invoke(self, payload: ToolPreInvokePayload, context: PluginContext) -> ToolPreInvokeResult:
        """Detect and mask PII in tool arguments before invocation.

        Args:
            payload: The tool payload containing arguments.
            context: Plugin execution context.

        Returns:
            Result with potentially modified tool arguments.
        """
        logger.debug(f"Processing tool pre-invoke for tool '{payload.name}' with {len(payload.args) if payload.args else 0} arguments")
        print("Here tool_pre_invoke --->", "Payload", payload, "Context", context)
        
        print("Here Gateway --->", context.global_context.metadata['gateway'])
        gw_id = context.global_context.server_id
        print("Gw id", gw_id)
        gateway_metadata = context.global_context.metadata['gateway']
        
        system_key: str | None = None
        if self._sconfig.system_handling == SystemHandling.TAG:
            system_tag = next((tag for tag in gateway_metadata.tags if tag.startswith(self._sconfig.system_tag_prefix)), None)
            match_exp = self._sconfig.system_tag_prefix + ":"
            if system_tag and system_tag.startswith(match_exp):
                system_key = system_tag.split(match_exp)[1]
                logger.info(f"Using vault system from GW tags: {system_key}")
            
        elif self._sconfig.system_handling == SystemHandling.OAUTH2_CONFIG:
            gen = get_db()
            db = next(gen)

            gateway_service = GatewayService()
            if gw_id:
                gateway = await gateway_service.get_gateway(db, gw_id)
                print("gateway used", gateway.oauth_config)
                if gateway.oauth_config:
                    token_url = gateway.oauth_config["token_url"]
                    parsed_url = urlparse(token_url)
                    system_key = parsed_url.hostname
                    logger.info(f"Using vault system from oauth_config: {system_key}")
                     
        if not system_key:
            logger.warning("System cannot be determined from gateway metadata.")
            return ToolPreInvokeResult()
   
        modified = False
        headers: dict[str, str] = payload.headers.model_dump() if payload.headers else {}
        
        vault_tokens: dict[str, str] = json.loads(headers[self._sconfig.vault_header_name])

        vault_handling = self._sconfig.vault_handling
            
        if system_key in vault_tokens:
            if vault_handling == VaultHandling.RAW:
                logger.info(f"Set Bearer token for system tag: {system_key} : {vault_tokens}")
                bearer_token: str = str(vault_tokens[system_key])
                headers["Authorization"] = f"Bearer {bearer_token}"
                modified = True
                del vault_tokens
            elif vault_handling == VaultHandling.UNWRAP:
   
                unwrapped_token: str = await async_unwrap_secret(system_key, vault_tokens[system_key])
                logger.info(f"Set Bearer token for system tag: {system_key} after unwrapping")
                headers["Authorization"] = f"Bearer {unwrapped_token}"
                modified = True
                del vault_tokens
            payload.headers = HttpHeaderPayload(root=headers)

        if modified:
            logger.info(f"Modified tool '{payload.name}' to add auth header")
            return ToolPreInvokeResult(modified_payload=payload)

        return ToolPreInvokeResult()
    
    async def shutdown(self) -> None:
        return None
