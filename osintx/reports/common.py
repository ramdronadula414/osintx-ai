"""Shared report semantics: facts, uncertainty, diagnostics, and suggestions."""
import json
from core.schema import Investigation

NOTICE = ('CONFIRMED means the source observation was directly obtained and parsed. It does not prove identity, '
          'ownership, authenticity, or current reachability. UNVERIFIED candidates and search suggestions are not discoveries. '
          'Numeric confidence is unassessed unless a stated evidence model exists. AI selects existing evidence only.')


def entity_rows(entities):
    return [[e.type.value, e.value, e.source, e.status.value, e.evidence,
             json.dumps(e.metadata, ensure_ascii=False, default=str)] for e in entities]


def tool_rows(inv: Investigation):
    return [[r.tool, r.status.value, r.error or '', str(len(r.entities))] for r in inv.tool_results]


def text_sections(inv: Investigation):
    return [('AI-prioritized executive evidence (extractive)', inv.ai_summary or f'Unavailable / skipped: {inv.ai_status.value}'),
            ('AI-prioritized technical evidence (extractive)', inv.ai_technical_summary or f'Unavailable / skipped: {inv.ai_status.value}')]
