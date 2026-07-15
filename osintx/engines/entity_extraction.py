"""Regex-based entity extraction used to pull structured entities out of
free-text tool output (e.g. a tool that only prints plain text rather than
structured JSON)."""
from __future__ import annotations

import re

from core.schema import Entity, EntityType

_PATTERNS = {
    EntityType.EMAIL: re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    EntityType.IP: re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    EntityType.URL: re.compile(r"https?://[^\s\"'<>]+"),
    EntityType.DOMAIN: re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}\b"),
}

_KNOWN_TECH_KEYWORDS = [
    "nginx", "apache", "wordpress", "react", "django", "flask", "laravel",
    "cloudflare", "aws", "docker", "kubernetes", "node.js", "express",
]


def extract_entities(text: str, source: str) -> list[Entity]:
    entities: list[Entity] = []
    for etype, pattern in _PATTERNS.items():
        for match in set(pattern.findall(text)):
            entities.append(Entity(type=etype, value=match, source=source, confidence=0.5))

    lowered = text.lower()
    for keyword in _KNOWN_TECH_KEYWORDS:
        if keyword in lowered:
            entities.append(Entity(type=EntityType.TECHNOLOGY, value=keyword, source=source, confidence=0.5))

    return entities
