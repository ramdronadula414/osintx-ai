"""Plugin architecture for OSINT-X AI.

A plugin lets someone add a new Linux tool integration (or an entirely new
investigation module) without touching the core framework. Drop a file into
plugins/installed/ that defines a subclass of `OsintxPlugin` and it will be
auto-discovered on next run.
"""
from __future__ import annotations

import importlib.util
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from core.schema import ToolResult

INSTALLED_DIR = Path(__file__).parent / "installed"


@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: str
    supported_targets: list[str] = field(default_factory=list)   # e.g. ["domain", "ip"]
    requires_binary: str | None = None                            # executable this plugin shells out to


class OsintxPlugin(ABC):
    metadata: PluginMetadata

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this plugin's dependencies (binary, API key, etc.) are met."""

    @abstractmethod
    def run(self, target: str, target_type: str, **kwargs) -> ToolResult:
        """Execute the plugin against `target` and return a normalized ToolResult."""


def discover_plugins() -> list[OsintxPlugin]:
    """Import every .py file under plugins/installed/ and instantiate any
    OsintxPlugin subclasses found inside."""
    plugins: list[OsintxPlugin] = []
    if not INSTALLED_DIR.exists():
        return plugins

    for py_file in INSTALLED_DIR.glob("*.py"):
        if py_file.stem.startswith("_"):
            continue
        module_name = f"osintx_plugin_{py_file.stem}"
        spec = importlib.util.spec_from_file_location(module_name, py_file)
        if not spec or not spec.loader:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception:
            continue

        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (
                isinstance(attr, type)
                and issubclass(attr, OsintxPlugin)
                and attr is not OsintxPlugin
            ):
                try:
                    plugins.append(attr())
                except Exception:
                    continue

    return plugins
