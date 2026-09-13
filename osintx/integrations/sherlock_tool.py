from __future__ import annotations

import re
from urllib.parse import urlsplit, unquote
from core.schema import Entity, EntityType, ToolResult, ResultStatus
from integrations.base import ToolIntegration
from utils.shell import CommandResult
from utils.validators import validate_username, validate_url, ValidationError

_FOUND = re.compile(r'^\[\+\]\s+([^:]+):\s+(https?://\S+)\s*$')


class SherlockIntegration(ToolIntegration):
    name = 'sherlock'

    def build_argv(self, target: str, timeout: int = 10, **kwargs) -> list[str]:
        return [self.executable_path, validate_username(target), '--timeout', str(timeout), '--print-found', '--no-color']

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        if not result.ok:
            return ToolResult.from_command(self.name, target, result)
        entities = []
        for line in result.stdout.splitlines():
            match = _FOUND.fullmatch(line.strip())
            if not match:
                continue
            try:
                url = validate_url(match[2])
            except ValidationError:
                continue
            parts = urlsplit(url)
            path = unquote(parts.path).strip('/')
            # Only a reported candidate, never proof from HTTP 200/403/429 or a redirect.
            if not path or any(p.lower() in {'login', 'signin', 'error', 'challenge'} for p in path.split('/')):
                continue
            tokens = re.split(r'[/@?=&.]+', path + '?' + unquote(parts.query))
            if target.casefold() not in [t.casefold() for t in tokens]:
                continue
            entities.append(Entity(EntityType.SOCIAL_ACCOUNT, url, self.name,
                                   status=ResultStatus.UNVERIFIED, url=url, evidence=line.strip(),
                                   metadata={'username': target, 'site': match[1]},
                                   confidence_basis='Sherlock reported this candidate; account existence and identity require independent review'))
        return ToolResult(self.name, target, True, entities=entities, raw_output=result.stdout,
                          status=ResultStatus.UNVERIFIED if entities else ResultStatus.UNKNOWN)
