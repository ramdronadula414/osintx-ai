from __future__ import annotations

import re
from core.schema import Entity, EntityType, ToolResult, ResultStatus
from integrations.base import ToolIntegration
from utils.shell import CommandResult
from utils.validators import validate_domain, validate_ip, ValidationError


class WhoisIntegration(ToolIntegration):
    name = 'whois'

    def build_argv(self, target: str, **kwargs) -> list[str]:
        try:
            target = validate_ip(target)
        except ValidationError:
            target = validate_domain(target)
        return [self.executable_path, target]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        if not result.ok:
            return ToolResult.from_command(self.name, target, result)
        text = result.stdout
        if re.search(r'(?im)^.*(?:rate limit|quota exceeded|too many requests)', text):
            return ToolResult(self.name, target, False, raw_output=text, status=ResultStatus.RATE_LIMITED, error='WHOIS rate limit')
        if re.search(r'(?im)^(?:No match for|NOT FOUND|No entries found|No Data Found)', text):
            return ToolResult(self.name, target, True, raw_output=text, status=ResultStatus.NOT_FOUND)
        entities = []
        patterns = {'registrar': r'Registrar', 'creation_date': r'Creation Date|created',
                    'expiration_date': r'Registry Expiry Date|Expiration Date', 'name_server': r'Name Server|nserver',
                    'org': r'Org(?:anization)?|OrgName|Registrant Organization|org-name',
                    'country': r'Country|Registrant Country', 'network': r'NetRange|inetnum|inet6num|CIDR',
                    'asn': r'OriginAS|origin'}
        for key, pattern in patterns.items():
            for match in re.finditer(rf'(?im)^({pattern}):[ \t]*(.+)$', text):
                value = match[2].strip()
                entities.append(Entity(EntityType.ORGANIZATION if key == 'org' else EntityType.METADATA,
                                       value, self.name, evidence=match[0], status=ResultStatus.CONFIRMED,
                                       metadata={'kind': key, 'target': target},
                                       confidence_basis='WHOIS reported this field; registration data may be stale, redacted, or self-reported'))
        return ToolResult(self.name, target, True, entities=entities, raw_output=text)
