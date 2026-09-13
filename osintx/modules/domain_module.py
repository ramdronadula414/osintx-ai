from __future__ import annotations

from core.schema import Investigation, ToolResult, ResultStatus
from modules.base import InvestigationModule
from plugins.base import discover_plugins
from utils.validators import validate_domain
from utils.logger import get_logger


class DomainModule(InvestigationModule):
    target_type = 'domain'

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_domain(target)
        self.run_tool('whois', target, investigation)
        self.run_dns(target, ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'], investigation)
        self.run_tool('theHarvester', target, investigation)
        if self.offline:
            investigation.add_tool_result(ToolResult('plugins', target, True, status=ResultStatus.NOT_REQUIRED, error='Offline mode: network plugins skipped'))
            return
        for plugin in discover_plugins(investigation.warnings):
            if 'domain' not in plugin.metadata.supported_targets:
                continue
            try:
                if plugin.is_available():
                    result = plugin.run(target, 'domain', timeout=self.timeout)
                else:
                    result = ToolResult(plugin.metadata.name, target, False, status=ResultStatus.TOOL_UNAVAILABLE, error='Plugin dependency unavailable')
            except Exception as exc:
                get_logger(__name__).error('Plugin failed (%s)', type(exc).__name__)
                result = ToolResult(plugin.metadata.name, target, False, error=f'Plugin failed ({type(exc).__name__})')
            investigation.add_tool_result(result)
