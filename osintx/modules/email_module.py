from __future__ import annotations

from core.schema import Entity, EntityType, Investigation
from integrations.registry import get_integration
from modules.base import InvestigationModule
from utils.logger import get_logger
from utils.validators import validate_email

log = get_logger(__name__)


class EmailModule(InvestigationModule):
    target_type = "email"

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_email(target)
        domain = target.split("@", 1)[1]

        investigation.entities.append(Entity(
            type=EntityType.EMAIL, value=target, source="input", confidence=1.0,
        ))

        # MX / SPF(TXT) / DMARC(TXT on _dmarc.<domain>) via dig
        if self.tool_registry.is_available("dig"):
            dig = get_integration("dig", self.tool_registry.path_for("dig"), self.timeout)

            mx_result = dig.run(domain, record_type="MX")
            mx_result.tool = "dig:MX"
            investigation.add_tool_result(mx_result)

            spf_result = dig.run(domain, record_type="TXT")
            spf_result.tool = "dig:SPF/TXT"
            investigation.add_tool_result(spf_result)

            dmarc_result = dig.run(f"_dmarc.{domain}", record_type="TXT")
            dmarc_result.tool = "dig:DMARC"
            investigation.add_tool_result(dmarc_result)
        else:
            log.warning("dig not installed — skipping MX/SPF/DMARC checks for %s", domain)

        if self.tool_registry.is_available("whois"):
            whois = get_integration("whois", self.tool_registry.path_for("whois"), self.timeout)
            investigation.add_tool_result(whois.run(domain))

        investigation.warnings.append(
            "Email investigation is limited to syntax validation and public DNS records "
            "(MX/SPF/DMARC/WHOIS). No credential or breach-database lookups are performed."
        )
