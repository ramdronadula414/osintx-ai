"""
Safe subprocess execution helpers.

Every external OSINT tool is invoked through `run_command`, which:
  * Never uses shell=True (no shell interpretation, no injection risk).
  * Accepts only list-form argv (no string concatenation of user input).
  * Enforces a timeout so a hung tool can't stall the whole investigation.
  * Captures stdout/stderr separately and never raises on non-zero exit
    (callers decide how to interpret tool-specific exit codes).
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional, Sequence


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def is_tool_available(name: str) -> bool:
    """Return True if `name` resolves to an executable on PATH."""
    return shutil.which(name) is not None


def resolve_tool_path(name: str, configured_path: Optional[str] = None) -> Optional[str]:
    """Prefer an explicit config path, otherwise auto-detect via PATH."""
    if configured_path:
        return configured_path if shutil.which(configured_path) or _is_executable(configured_path) else None
    return shutil.which(name)


def _is_executable(path: str) -> bool:
    import os
    return os.path.isfile(path) and os.access(path, os.X_OK)


def run_command(
    argv: Sequence[str],
    timeout: int = 30,
    cwd: Optional[str] = None,
) -> CommandResult:
    """
    Execute argv safely (no shell). argv[0] should already be a resolved,
    known-good executable path/name; every other element is treated as an
    opaque argument string, never interpolated into a shell command.
    """
    argv = list(argv)
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            shell=False,          # critical: never let the shell parse args
        )
        return CommandResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            argv=argv,
            returncode=-1,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
            timed_out=True,
        )
    except FileNotFoundError:
        return CommandResult(argv=argv, returncode=127, stdout="", stderr="executable not found")
