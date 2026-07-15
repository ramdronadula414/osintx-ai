from __future__ import annotations

import re

from core.schema import Entity, EntityType, ToolResult
from integrations.base import ToolIntegration
from utils.shell import CommandResult

_URL_RE = re.compile(r"https?://\S+")


class SherlockIntegration(ToolIntegration):
    """Wraps the Sherlock project (public-profile username search across
    hundreds of sites). Only ever queried with a username the analyst
    supplied; never used to brute-force or guess identities."""
    name = "sherlock"

    def build_argv(self, target: str, timeout: int = 10, **kwargs) -> list[str]:
        return [
            self.executable_path,
            target,
            "--timeout", str(timeout),
            "--print-found",
            "--no-color",
        ]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        entities: list[Entity] = []
        for line in (result.stdout or "").splitlines():
            match = _URL_RE.search(line)
            if match and ("found" in line.lower() or match):
                url = match.group(0)
                entities.append(Entity(
                    type=EntityType.SOCIAL_ACCOUNT,
                    value=url,
                    source="sherlock",
                    confidence=0.75,
                    metadata={"username": target},
                ))
        return ToolResult(
            tool=self.name, target=target, success=result.ok or bool(entities),
            entities=entities, raw_output=result.stdout,
            error=None if (result.ok or entities) else result.stderr,
        )
