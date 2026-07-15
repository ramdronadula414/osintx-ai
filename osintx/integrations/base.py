"""Base class every tool integration wrapper inherits from.

An integration's job is narrow and mechanical:
  1. Build a safe argv list for the underlying Linux tool.
  2. Run it through utils.shell.run_command (never shell=True).
  3. Parse whatever that tool prints into a ToolResult full of Entity
     objects using the unified schema.

Nothing here ever bypasses auth, scrapes behind a login, or touches
non-public data — integrations only shell out to the same public-data
tools an analyst would run by hand.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod

from core.schema import ToolResult
from utils.shell import CommandResult, run_command


class ToolIntegration(ABC):
    name: str = "base"

    def __init__(self, executable_path: str, timeout: int = 30):
        self.executable_path = executable_path
        self.timeout = timeout

    @abstractmethod
    def build_argv(self, target: str, **kwargs) -> list[str]:
        """Return a safe argv list (no shell strings) for this target."""

    @abstractmethod
    def parse(self, target: str, result: CommandResult) -> ToolResult:
        """Convert raw CommandResult into a normalized ToolResult."""

    def run(self, target: str, **kwargs) -> ToolResult:
        start = time.monotonic()
        argv = self.build_argv(target, **kwargs)
        cmd_result = run_command(argv, timeout=self.timeout)
        tool_result = self.parse(target, cmd_result)
        tool_result.duration_seconds = round(time.monotonic() - start, 3)
        return tool_result
