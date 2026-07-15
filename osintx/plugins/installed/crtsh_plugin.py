"""Example plugin: queries crt.sh's public JSON API for certificate
transparency log entries to discover subdomains. Demonstrates a
non-subprocess plugin (pure HTTP to a public data source) so plugin authors
can see both patterns."""
from __future__ import annotations

import json

import requests

from core.schema import Entity, EntityType, ToolResult
from plugins.base import OsintxPlugin, PluginMetadata


class CrtShPlugin(OsintxPlugin):
    metadata = PluginMetadata(
        name="crt.sh Certificate Transparency",
        version="1.0.0",
        author="OSINT-X AI Team",
        description="Discovers subdomains from public certificate transparency logs via crt.sh",
        supported_targets=["domain"],
        requires_binary=None,
    )

    def is_available(self) -> bool:
        try:
            requests.head("https://crt.sh/", timeout=5)
            return True
        except requests.RequestException:
            return False

    def run(self, target: str, target_type: str, **kwargs) -> ToolResult:
        entities = []
        error = None
        try:
            resp = requests.get(
                "https://crt.sh/", params={"q": f"%.{target}", "output": "json"}, timeout=15
            )
            resp.raise_for_status()
            records = json.loads(resp.text)
            seen = set()
            for record in records:
                name_value = record.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.").rstrip(".")
                    if name and name.endswith(target) and name not in seen:
                        seen.add(name)
                        entities.append(Entity(
                            type=EntityType.SUBDOMAIN, value=name,
                            source="crt.sh", confidence=0.75,
                        ))
        except (requests.RequestException, json.JSONDecodeError) as exc:
            error = str(exc)

        return ToolResult(
            tool="crt.sh", target=target, success=error is None,
            entities=entities, raw_output="", error=error,
        )
