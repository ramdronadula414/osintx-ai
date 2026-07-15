from __future__ import annotations

import json
import re

from core.schema import Entity, EntityType, ToolResult
from integrations.base import ToolIntegration
from utils.shell import CommandResult

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9-]{1,63})+$")


class TheHarvesterIntegration(ToolIntegration):
    """Wraps theHarvester for passive collection of emails and subdomains
    from public sources (search engines, cert transparency, etc.)."""
    name = "theHarvester"

    def build_argv(self, target: str, sources: str = "all", limit: int = 200, **kwargs) -> list[str]:
        return [
            self.executable_path,
            "-d", target,
            "-b", sources,
            "-l", str(limit),
        ]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        text = result.stdout or ""
        entities: list[Entity] = []

        for email in set(_EMAIL_RE.findall(text)):
            entities.append(Entity(type=EntityType.EMAIL, value=email, source="theHarvester", confidence=0.7))

        for line in text.splitlines():
            candidate = line.strip().rstrip(".")
            if candidate.endswith(target) and _HOST_RE.match(candidate) and candidate != target:
                entities.append(Entity(
                    type=EntityType.SUBDOMAIN, value=candidate, source="theHarvester", confidence=0.7,
                ))

        return ToolResult(
            tool=self.name, target=target, success=result.ok,
            entities=entities, raw_output=text[:20000],
            error=None if result.ok else result.stderr,
        )
