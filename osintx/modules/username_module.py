from __future__ import annotations

from core.schema import Investigation
from integrations.registry import get_integration
from modules.base import InvestigationModule
from utils.logger import get_logger
from utils.validators import validate_username

log = get_logger(__name__)


class UsernameModule(InvestigationModule):
    target_type = "username"

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_username(target)

        if self.tool_registry.is_available("sherlock"):
            sherlock = get_integration("sherlock", self.tool_registry.path_for("sherlock"), self.timeout * 3)
            investigation.add_tool_result(sherlock.run(target))
        else:
            log.warning("sherlock not installed — skipping username enumeration for %s", target)
            investigation.warnings.append(
                "Sherlock is not installed; username search skipped. "
                "Install via: pip install sherlock-project"
            )

        if self.tool_registry.is_available("maigret"):
            # Maigret has no dedicated parser yet — captured as raw output only.
            from utils.shell import run_command
            argv = [self.tool_registry.path_for("maigret"), target, "--json", "simple"]
            result = run_command(argv, timeout=self.timeout * 4)
            from core.schema import ToolResult
            investigation.add_tool_result(ToolResult(
                tool="maigret", target=target, success=result.ok,
                entities=[], raw_output=result.stdout[:20000],
                error=None if result.ok else result.stderr,
            ))
