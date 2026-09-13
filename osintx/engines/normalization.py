"""Deduplicate equal observations without inventing confidence or provenance."""
from __future__ import annotations

from dataclasses import asdict
from core.schema import Entity


def normalize_entities(entities: list[Entity]) -> list[Entity]:
    merged = {}
    for entity in entities:
        if not entity.value.strip():
            continue
        key = entity.dedupe_key()
        if key not in merged:
            merged[key] = entity
            entity.metadata.setdefault('all_sources', [entity.source])
            continue
        existing = merged[key]
        sources = set(existing.metadata.get('all_sources', [existing.source]))
        sources.update(entity.metadata.get('all_sources', [entity.source]))
        existing.metadata['all_sources'] = sorted(sources)
        observation = {k: v for k, v in asdict(entity).items() if k != 'id'}
        observations = existing.metadata.setdefault('additional_observations', [])
        if observation not in observations:
            observations.append(observation)
        # Tools may share upstream sources; repetition never increases confidence.
    return list(merged.values())
