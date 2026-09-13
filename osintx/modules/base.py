from __future__ import annotations

from abc import ABC, abstractmethod
from core.schema import Investigation, ToolResult, ResultStatus
from core.tool_registry import ToolRegistry
from integrations.registry import get_integration
from utils.validators import ValidationError
from utils.logger import get_logger


class InvestigationModule(ABC):
    target_type: str = 'base'

    def __init__(self, tool_registry: ToolRegistry, timeout: int = 30, offline: bool = False):
        self.tool_registry = tool_registry
        self.timeout = timeout
        self.offline = offline

    def run_tool(self, name, target, investigation, *, local=False, **kwargs):
        if self.offline and not local:
            result = ToolResult(name, target, True, status=ResultStatus.NOT_REQUIRED, error='Offline mode: network-dependent tool skipped')
        elif not self.tool_registry.is_available(name):
            result = ToolResult(name, target, False, status=ResultStatus.TOOL_UNAVAILABLE, error='Optional tool not installed or not executable')
        else:
            integration = get_integration(name, self.tool_registry.path_for(name), self.timeout)
            try:
                result = integration.run(target, **kwargs)
            except ValidationError:
                raise
            except Exception as exc:  # Isolate third-party wrappers while preserving the failed step.
                get_logger(__name__).error('Tool %s failed (%s)', name, type(exc).__name__)
                result = ToolResult(name, target, False, error=f'Tool wrapper failed ({type(exc).__name__})')
        investigation.add_tool_result(result)
        return result

    def run_dns(self, target, record_types, investigation):
        if self.offline:
            investigation.add_tool_result(ToolResult('dns', target, True, status=ResultStatus.NOT_REQUIRED, error='Offline mode: DNS skipped'))
            return
        if self.tool_registry.is_available('dig'):
            for rtype in record_types:
                result = self.run_tool('dig', target, investigation, record_type=rtype)
                result.tool = f'dig:{rtype}'
        else:
            investigation.add_tool_result(ToolResult('dig', target, False, status=ResultStatus.TOOL_UNAVAILABLE, error='Using dnspython fallback'))
            from integrations.dns_python import lookup
            for rtype in record_types:
                investigation.add_tool_result(lookup(target, rtype, self.timeout))

    @abstractmethod
    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        """Populate the investigation with independently classified source results."""
