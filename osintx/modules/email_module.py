from __future__ import annotations

from core.schema import Investigation
from modules.base import InvestigationModule
from utils.validators import validate_email


class EmailModule(InvestigationModule):
    target_type = 'email'

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_email(target)
        domain = target.rsplit('@', 1)[1]
        self.run_dns(domain, ['MX', 'TXT'], investigation)
        self.run_dns('_dmarc.' + domain, ['TXT'], investigation)
        self.run_tool('whois', domain, investigation)
        investigation.warnings.append('Email syntax is valid. Mailbox existence, account ownership, and breach status are UNKNOWN; DNS describes the domain only.')
