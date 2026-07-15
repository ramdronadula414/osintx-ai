from __future__ import annotations

from core.schema import Investigation
from integrations.registry import get_integration
from modules.base import InvestigationModule
from utils.logger import get_logger
from utils.validators import is_private_ip, validate_ip

log = get_logger(__name__)


class IPModule(InvestigationModule):
    target_type = "ip"

    def run(self, target: str, investigation: Investigation, allow_port_scan: bool = False, **kwargs) -> None:
        target = validate_ip(target)

        if is_private_ip(target):
            investigation.warnings.append(
                f"'{target}' is a private/loopback address — public OSINT sources will return no data."
            )

        if self.tool_registry.is_available("whois"):
            whois = get_integration("whois", self.tool_registry.path_for("whois"), self.timeout)
            investigation.add_tool_result(whois.run(target))
        else:
            log.warning("whois not installed — skipping WHOIS/ASN lookup for %s", target)

        if allow_port_scan and self.tool_registry.is_available("nmap"):
            nmap = get_integration("nmap", self.tool_registry.path_for("nmap"), self.timeout * 4)
            investigation.add_tool_result(nmap.run(target))
        elif not allow_port_scan:
            investigation.warnings.append(
                "Port scanning was skipped: pass --i-have-authorization to scan a target "
                "you own or are authorized to test."
            )
        else:
            log.warning("nmap not installed — skipping port/service scan for %s", target)
