from __future__ import annotations

import re

from core.schema import Entity, EntityType, ToolResult
from integrations.base import ToolIntegration
from utils.shell import CommandResult


class WhoisIntegration(ToolIntegration):
    name = "whois"

    def build_argv(self, target: str, **kwargs) -> list[str]:
        return [self.executable_path, target]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        entities: list[Entity] = []
        text = result.stdout or ""

        patterns = {
            "registrar": r"(?im)^Registrar:\s*(.+)$",
            "creation_date": r"(?im)^Creation Date:\s*(.+)$",
            "expiration_date": r"(?im)^(?:Registry Expiry Date|Expiration Date):\s*(.+)$",
            "name_server": r"(?im)^Name Server:\s*(.+)$",
            "org": r"(?im)^(?:Org(?:anization)?|OrgName):\s*(.+)$",
            "country": r"(?im)^Country:\s*(.+)$",
        }

        metadata = {}
        for key, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                metadata[key] = matches if len(matches) > 1 else matches[0]

        if metadata.get("org"):
            org_val = metadata["org"] if isinstance(metadata["org"], str) else metadata["org"][0]
            entities.append(Entity(
                type=EntityType.ORGANIZATION, value=org_val, source="whois",
                confidence=0.6, metadata={"context": "registrant/org from WHOIS"},
            ))

        return ToolResult(
            tool=self.name,
            target=target,
            success=result.ok,
            entities=entities,
            raw_output=text[:20000],
            error=None if result.ok else (result.stderr or "whois lookup failed"),
        )
