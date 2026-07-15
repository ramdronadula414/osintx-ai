from __future__ import annotations

import re

from core.schema import Entity, EntityType, ToolResult
from integrations.base import ToolIntegration
from utils.shell import CommandResult

_PORT_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$")


class NmapIntegration(ToolIntegration):
    """Wraps nmap for a conservative default scan (top ports, service
    detection, no vuln scripts). The CLI layer must confirm the analyst
    has explicit authorization before this ever runs — see
    `security.allow_port_scanning` in config and the CLI's `--i-have-authorization` flag."""
    name = "nmap"

    def build_argv(self, target: str, top_ports: int = 100, **kwargs) -> list[str]:
        return [
            self.executable_path,
            "-sT",                     # TCP connect scan only, no raw-socket SYN scan
            "--top-ports", str(top_ports),
            "-sV",                     # service/version detection
            "-Pn",
            target,
        ]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        entities: list[Entity] = []
        for line in (result.stdout or "").splitlines():
            match = _PORT_LINE_RE.match(line.strip())
            if match:
                port, proto, state, service = match.groups()
                if state == "open":
                    entities.append(Entity(
                        type=EntityType.URL,
                        value=f"{target}:{port}/{proto}",
                        source="nmap",
                        confidence=0.85,
                        metadata={"service": service.strip(), "state": state},
                    ))
        return ToolResult(
            tool=self.name, target=target, success=result.ok,
            entities=entities, raw_output=result.stdout,
            error=None if result.ok else result.stderr,
        )
