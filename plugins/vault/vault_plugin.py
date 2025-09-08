# -*- coding: utf-8 -*-

from pydantic import BaseModel


from mcpgateway.plugins.framework import (
    Plugin,
    PluginConfig,
    PluginContext,
    ToolPreInvokePayload,
    ToolPreInvokeResult,
)

from mcpgateway.services.logging_service import LoggingService
from mcpgateway.services.gateway_service import GatewayService
from mcpgateway.db import get_db

# Initialize logging service first
logging_service = LoggingService()
logger = logging_service.get_logger(__name__)

class VaultConfig(BaseModel):
    system_tag_prefix: str = "system"


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
        gw_id = context.global_context.server_id
        print("Gw id", gw_id)
        if not payload.args:
            return ToolPreInvokeResult()

        modified = False
         
        gen = get_db()
        db = next(gen)
        
        gateway_service = GatewayService()
        if gw_id:
            gateway = await gateway_service.get_gateway(db, gw_id)
            print("gateway used", gateway)

        if modified:
            logger.info(f"Modified tool '{payload.name}' arguments to mask PII")
            return ToolPreInvokeResult(modified_payload=payload)

        return ToolPreInvokeResult()
    async def shutdown(self) -> None:
        return None
