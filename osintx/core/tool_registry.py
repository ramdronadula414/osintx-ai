"""Detects which of the supported Linux OSINT tools are installed and
exposes a single registry the rest of the framework queries instead of
each module re-implementing `shutil.which` checks."""
from __future__ import annotations

from dataclasses import dataclass

from utils.shell import resolve_tool_path

SUPPORTED_TOOLS = [
    "sherlock", "maigret", "theHarvester", "photon", "spiderfoot",
    "amass", "subfinder", "assetfinder", "findomain", "dnsrecon",
    "dig", "whois", "nmap", "naabu", "httpx", "katana", "whatweb",
    "exiftool", "tesseract", "socialscan", "git", "trufflehog",
    "waybackurls", "gau", "dnsx", "nslookup", "masscan", "jq", "python3", "yt-dlp",
]


@dataclass
class ToolStatus:
    name: str
    available: bool
    path: str | None
    state: str = "NOT INSTALLED"
    integrated: bool = False


class ToolRegistry:
    def __init__(self, configured_paths: dict | None = None):
        self.configured_paths = configured_paths or {}
        self._status: dict[str, ToolStatus] = {}
        self._detect_all()

    def _detect_all(self):
        for name in SUPPORTED_TOOLS:
            configured = self.configured_paths.get(name, self.configured_paths.get(name.lower()))
            path = resolve_tool_path(name, configured)
            self._status[name] = ToolStatus(name=name, available=path is not None, path=path,
                                            state='AVAILABLE' if path else 'FAILED' if configured else 'NOT INSTALLED',
                                            integrated=name in {'whois', 'dig', 'sherlock', 'theHarvester', 'nmap', 'exiftool', 'maigret', 'tesseract'})

    def is_available(self, name: str) -> bool:
        status = self._status.get(name)
        return bool(status and status.available)

    def path_for(self, name: str) -> str | None:
        status = self._status.get(name)
        return status.path if status else None

    def available_tools(self) -> list[str]:
        return [n for n, s in self._status.items() if s.available]

    def missing_tools(self) -> list[str]:
        return [n for n, s in self._status.items() if not s.available]

    def summary_table_rows(self) -> list[tuple[str, str]]:
        return [(name, s.state + (" (detection only; NOT REQUIRED)" if not s.integrated else ""))
                for name, s in sorted(self._status.items())]
