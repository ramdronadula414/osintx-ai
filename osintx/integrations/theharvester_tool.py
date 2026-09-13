from __future__ import annotations

import re
from core.schema import Entity, EntityType, ToolResult, ResultStatus
from integrations.base import ToolIntegration
from utils.shell import CommandResult
from utils.validators import validate_domain, validate_email, ValidationError


class TheHarvesterIntegration(ToolIntegration):
    name = 'theHarvester'

    def build_argv(self, target: str, sources: str = 'crtsh', limit: int = 200, **kwargs) -> list[str]:
        if not re.fullmatch(r'[A-Za-z0-9_,]+', sources) or not 1 <= limit <= 1000:
            raise ValueError('Invalid passive source/limit')
        return [self.executable_path, '-d', validate_domain(target), '-b', sources, '-l', str(limit)]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        if not result.ok:
            return ToolResult.from_command(self.name, target, result)
        target = validate_domain(target)
        entities = []
        section = None
        for line in result.stdout.splitlines():
            text = line.strip()
            if text.startswith('[*]'):
                section = 'email' if re.match(r'\[\*\] Emails found:', text, re.I) else 'host' if re.match(r'\[\*\] Hosts found:', text, re.I) else None
                continue
            if not section or text.startswith(('[', '-', '*')):
                continue
            try:
                value = validate_email(text) if section == 'email' else validate_domain(text.split(':', 1)[0])
                host = value.rsplit('@', 1)[-1]
                if host != target and not host.endswith('.' + target):
                    continue
            except ValidationError:
                continue
            entities.append(Entity(EntityType.EMAIL if section == 'email' else EntityType.SUBDOMAIN,
                                   value, self.name, evidence=text, status=ResultStatus.UNVERIFIED,
                                   confidence_basis='Tool-reported candidate; original source and current existence are not independently verified'))
        return ToolResult(self.name, target, True, entities=entities, raw_output=result.stdout,
                          status=ResultStatus.UNVERIFIED if entities else ResultStatus.UNKNOWN)
