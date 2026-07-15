"""Builds a chronological timeline from any timestamped data found across
entities and tool results (e.g. domain creation date, EXIF capture date,
certificate issuance date)."""
from __future__ import annotations

from core.schema import Entity, TimelineEvent, ToolResult

_TIMESTAMP_METADATA_KEYS = [
    "creation_date", "expiration_date", "issued_date", "captured_at", "first_seen",
]


def build_timeline(entities: list[Entity], tool_results: list[ToolResult]) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    for entity in entities:
        if entity.first_seen:
            events.append(TimelineEvent(
                timestamp=entity.first_seen,
                description=f"{entity.type.value} '{entity.value}' first observed",
                source=entity.source,
                entity_ids=[entity.id],
            ))
        for key in _TIMESTAMP_METADATA_KEYS:
            value = entity.metadata.get(key)
            if value:
                events.append(TimelineEvent(
                    timestamp=str(value),
                    description=f"{key.replace('_', ' ').title()} for {entity.type.value} '{entity.value}'",
                    source=entity.source,
                    entity_ids=[entity.id],
                ))

    for tr in tool_results:
        events.append(TimelineEvent(
            timestamp=tr.started_at,
            description=f"Ran {tr.tool} against '{tr.target}' ({'success' if tr.success else 'failed'})",
            source=tr.tool,
        ))

    events.sort(key=lambda e: e.timestamp)
    return events
