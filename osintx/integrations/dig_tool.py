from __future__ import annotations

from core.schema import Entity, EntityType, ToolResult
from integrations.base import ToolIntegration
from utils.shell import CommandResult

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DigIntegration(ToolIntegration):
    """Wraps `dig` to pull the record types most relevant to OSINT
    (A/AAAA for hosting, MX for mail infra, TXT for SPF/DMARC/verification
    strings, NS for delegation)."""
    name = "dig"

    def build_argv(self, target: str, record_type: str = "A", **kwargs) -> list[str]:
        return [self.executable_path, "+noall", "+answer", target, record_type]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        entities: list[Entity] = []
        for line in (result.stdout or "").splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            rtype, value = parts[3], parts[4]
            if rtype == "A":
                entities.append(Entity(type=EntityType.IP, value=value, source="dig", confidence=0.9))
            elif rtype == "AAAA":
                entities.append(Entity(type=EntityType.IP, value=value, source="dig", confidence=0.9))
            elif rtype == "MX":
                entities.append(Entity(type=EntityType.DOMAIN, value=parts[-1].rstrip("."),
                                        source="dig", confidence=0.8, metadata={"record": "MX"}))
            elif rtype == "NS":
                entities.append(Entity(type=EntityType.DOMAIN, value=value.rstrip("."),
                                        source="dig", confidence=0.8, metadata={"record": "NS"}))

        return ToolResult(
            tool=self.name, target=target, success=result.ok,
            entities=entities, raw_output=result.stdout,
            error=None if result.ok else result.stderr,
        )

    def run_all_record_types(self, target: str) -> list[ToolResult]:
        results = []
        for rtype in RECORD_TYPES:
            argv = self.build_argv(target, record_type=rtype)
            from utils.shell import run_command
            cmd_result = run_command(argv, timeout=self.timeout)
            tr = self.parse(target, cmd_result)
            tr.tool = f"dig:{rtype}"
            results.append(tr)
        return results
