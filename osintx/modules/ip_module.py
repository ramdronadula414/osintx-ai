from __future__ import annotations

import ipaddress
from core.schema import Investigation, ToolResult, ResultStatus
from modules.base import InvestigationModule
from utils.validators import is_private_ip, validate_ip


class IPModule(InvestigationModule):
    target_type = 'ip'

    def run(self, target: str, investigation: Investigation, allow_port_scan: bool = False, **kwargs) -> None:
        target = validate_ip(target)
        if is_private_ip(target):
            investigation.add_tool_result(ToolResult('public_ip_lookup', target, True, status=ResultStatus.NOT_REQUIRED, error='Non-global IP: public WHOIS and reverse DNS skipped'))
        else:
            self.run_tool('whois', target, investigation)
            self.run_dns(ipaddress.ip_address(target).reverse_pointer, ['PTR'], investigation)
        if allow_port_scan:
            self.run_tool('nmap', target, investigation)
        else:
            investigation.add_tool_result(ToolResult('nmap', target, True, status=ResultStatus.NOT_REQUIRED, error='Port scan requires --i-have-authorization for an owned/authorized target'))
