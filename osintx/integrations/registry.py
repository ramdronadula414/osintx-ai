"""Maps a tool name to its integration wrapper class.

Only tools with a dedicated parser are listed here. Any other tool in
core.tool_registry.SUPPORTED_TOOLS that lacks a wrapper is still detected
(so `osintx config` / `osintx --help` can report it) but is skipped during
investigation until a plugin or wrapper is added — see plugins/README.md
for how to add one without touching this core file.
"""
from __future__ import annotations

from integrations.dig_tool import DigIntegration
from integrations.exiftool_tool import ExifToolIntegration
from integrations.nmap_tool import NmapIntegration
from integrations.sherlock_tool import SherlockIntegration
from integrations.theharvester_tool import TheHarvesterIntegration
from integrations.whois_tool import WhoisIntegration

INTEGRATION_CLASSES = {
    "whois": WhoisIntegration,
    "dig": DigIntegration,
    "sherlock": SherlockIntegration,
    "theHarvester": TheHarvesterIntegration,
    "nmap": NmapIntegration,
    "exiftool": ExifToolIntegration,
}


def get_integration(name: str, path: str, timeout: int = 30):
    cls = INTEGRATION_CLASSES.get(name)
    if cls is None:
        return None
    return cls(executable_path=path, timeout=timeout)
