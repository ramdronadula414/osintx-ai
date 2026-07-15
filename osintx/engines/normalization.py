"""Merges duplicate entities collected by different tools (e.g. Sherlock
and Maigret both finding the same GitHub profile) into a single entity with
combined sources and an adjusted confidence score."""
from __future__ import annotations

from core.schema import Entity


def normalize_entities(entities: list[Entity]) -> list[Entity]:
    merged: dict[tuple, Entity] = {}

    for entity in entities:
        key = entity.dedupe_key()
        if key not in merged:
            merged[key] = entity
        else:
            existing = merged[key]
            sources = set(existing.metadata.get("all_sources", [existing.source]))
            sources.add(entity.source)
            existing.metadata["all_sources"] = sorted(sources)
            # Corroboration by multiple independent tools raises confidence,
            # capped at 0.99 (AI/tool output is never treated as certain).
            existing.confidence = min(0.99, max(existing.confidence, entity.confidence) + 0.05 * (len(sources) - 1))

    return list(merged.values())
