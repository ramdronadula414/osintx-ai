from __future__ import annotations

from abc import ABC, abstractmethod

from core.schema import Investigation
from core.tool_registry import ToolRegistry


class InvestigationModule(ABC):
    target_type: str = "base"

    def __init__(self, tool_registry: ToolRegistry, timeout: int = 30):
        self.tool_registry = tool_registry
        self.timeout = timeout

    @abstractmethod
    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        """Populate `investigation` with tool_results/entities. Mutates in place."""
