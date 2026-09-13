from __future__ import annotations

import re

from core.schema import Entity, EntityType, ToolResult, ResultStatus
from integrations.base import ToolIntegration
from utils.shell import CommandResult
from utils.validators import validate_ip

_PORT_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$")


class NmapIntegration(ToolIntegration):
    """Wraps nmap for a conservative default scan (top ports, service
    detection, no vuln scripts). The CLI layer must confirm the analyst
    has explicit authorization before this ever runs — see
    `security.allow_port_scanning` in config and the CLI's `--i-have-authorization` flag."""
    name = "nmap"

    def build_argv(self, target: str, top_ports: int = 100, **kwargs) -> list[str]:
        target = validate_ip(target)
        if not 1 <= top_ports <= 1000:
            raise ValueError("top_ports must be between 1 and 1000")
        return [
            self.executable_path,
            *(["-6"] if ":" in target else []),
            "-sT",                     # TCP connect scan only, no raw-socket SYN scan
            "--top-ports", str(top_ports),
            "-sV",                     # service/version detection
            "-Pn",
            target,
        ]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        if not result.ok:
            return ToolResult.from_command(self.name, target, result)
        entities: list[Entity] = []
        for line in (result.stdout or "").splitlines():
            match = _PORT_LINE_RE.match(line.strip())
            if match:
                port, proto, state, service = match.groups()
                if state == "open":
                    entities.append(Entity(
                        type=EntityType.NETWORK_SERVICE,
                        value=f"[{target}]:{port}/{proto}" if ":" in target else f"{target}:{port}/{proto}",
                        source="nmap",
                        status=ResultStatus.CONFIRMED, evidence=line.strip(),
                        confidence_basis="Observed open port; service/version is Nmap interpretation",
                        metadata={"service": service.strip(), "state": state},
                    ))
        return ToolResult.from_command(self.name, target, result, entities)
