from __future__ import annotations

import html
import re
from core.schema import Investigation
from reports.common import NOTICE, entity_rows, tool_rows, text_sections


def _esc(value):
    value = html.escape(str(value), quote=False).replace('\n', ' / ').replace('\r', '')
    return re.sub(r'([\\`*_{}\[\]()#+.!|>-])', r'\\\1', value)


def _table(headers, rows):
    return ['| ' + ' | '.join(map(_esc, headers)) + ' |', '|' + '|'.join(['---'] * len(headers)) + '|'] + [
        '| ' + ' | '.join(map(_esc, row)) + ' |' for row in rows]


def generate_markdown(inv: Investigation) -> str:
    lines = ['# OSINT-X AI Investigation Report', '', f'**ID:** {_esc(inv.id)}', '',
             f'**Target:** {_esc(inv.target_type)} = {_esc(inv.target_value)}', '',
             f'**Started:** {_esc(inv.started_at)}', '', f'**Completed:** {_esc(inv.completed_at)}', '', NOTICE, '']
    for title, text in text_sections(inv):
        lines += ['## ' + title, '', _esc(text), '']
    for title, entities in inv.entity_groups():
        lines += ['## ' + title, '']
        lines += _table(['Type', 'Value', 'Source', 'Status', 'Evidence', 'Metadata'], entity_rows(entities)) if entities else ['None.']
        lines += ['']
    lines += ['## Source results / errors / unavailable sources', ''] + _table(['Source', 'Status', 'Details', 'Entities'], tool_rows(inv)) + ['']
    lines += ['## Search suggestions — UNVERIFIED', ''] + [_esc(s['label']) + ': ' + _esc(s['url']) for s in inv.suggestions] + ['']
    lines += ['## Heuristic exposure assessment', '', _esc(str(inv.risk)), '']
    lines += ['## Timeline (source observations)', ''] + [_esc(f'{e.timestamp}: {e.description}') for e in inv.timeline] + ['']
    lines += ['## AI-selected follow-up actions', ''] + ['- ' + _esc(r) for r in inv.ai_recommendations] + ['']
    lines += ['## Warnings / limitations', ''] + ['- ' + _esc(w) for w in inv.warnings]
    return '\n'.join(lines)
