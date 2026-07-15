from __future__ import annotations

from core.schema import Investigation
from integrations.registry import get_integration
from modules.base import InvestigationModule
from plugins.base import discover_plugins
from utils.logger import get_logger
from utils.validators import validate_domain

log = get_logger(__name__)


class DomainModule(InvestigationModule):
    target_type = "domain"

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_domain(target)

        # WHOIS
        if self.tool_registry.is_available("whois"):
            whois = get_integration("whois", self.tool_registry.path_for("whois"), self.timeout)
            investigation.add_tool_result(whois.run(target))
        else:
            log.warning("whois not installed — skipping WHOIS lookup for %s", target)

        # DNS (A/AAAA/MX/NS/TXT/CNAME/SOA)
        if self.tool_registry.is_available("dig"):
            dig = get_integration("dig", self.tool_registry.path_for("dig"), self.timeout)
            for tr in dig.run_all_record_types(target):
                investigation.add_tool_result(tr)
        else:
            log.warning("dig not installed — skipping DNS record enumeration for %s", target)

        # theHarvester (subdomains + emails from public sources)
        if self.tool_registry.is_available("theHarvester"):
            harvester = get_integration("theHarvester", self.tool_registry.path_for("theHarvester"), self.timeout * 3)
            investigation.add_tool_result(harvester.run(target))
        else:
            log.warning("theHarvester not installed — skipping passive subdomain/email harvest for %s", target)

        # Plugins that support "domain" targets (e.g. crt.sh)
        for plugin in discover_plugins():
            if "domain" in plugin.metadata.supported_targets and plugin.is_available():
                try:
                    investigation.add_tool_result(plugin.run(target, "domain"))
                except Exception as exc:  # noqa: BLE001
                    investigation.warnings.append(f"Plugin '{plugin.metadata.name}' failed: {exc}")
