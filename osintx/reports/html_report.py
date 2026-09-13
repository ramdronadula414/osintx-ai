from __future__ import annotations

import html
from core.schema import Investigation
from reports.common import NOTICE, entity_rows, tool_rows, text_sections


def _esc(value):
    return html.escape(str(value))


def _table(headers, rows):
    return '<table><thead><tr>' + ''.join('<th>' + _esc(h) + '</th>' for h in headers) + '</tr></thead><tbody>' + ''.join(
        '<tr>' + ''.join('<td>' + _esc(v) + '</td>' for v in row) + '</tr>' for row in rows) + '</tbody></table>'


def generate_html(inv: Investigation) -> str:
    parts = ['<!doctype html><html lang="en"><meta charset="utf-8"><title>OSINT-X AI Report</title>',
             '<style>body{font-family:system-ui;max-width:1200px;margin:2rem auto;padding:1rem;color:#192333}table{border-collapse:collapse;width:100%;table-layout:fixed}td,th{border:1px solid #ccd;padding:.5rem;text-align:left;overflow-wrap:anywhere}p{white-space:pre-wrap}h2{margin-top:2rem}</style>',
             '<h1>OSINT-X AI Investigation Report</h1>', f'<p>ID: {_esc(inv.id)}\nTarget: {_esc(inv.target_type)} = {_esc(inv.target_value)}\nStarted: {_esc(inv.started_at)}\nCompleted: {_esc(inv.completed_at)}</p>', '<p>' + NOTICE + '</p>']
    for title, text in text_sections(inv):
        parts += ['<h2>' + title + '</h2><p>' + _esc(text) + '</p>']
    for title, entities in inv.entity_groups():
        parts += ['<h2>' + title + '</h2>', _table(['Type', 'Value', 'Source', 'Status', 'Evidence', 'Metadata'], entity_rows(entities)) if entities else '<p>None.</p>']
    parts += ['<h2>Source results / errors / unavailable sources</h2>', _table(['Source', 'Status', 'Details', 'Entities'], tool_rows(inv)), '<h2>Search suggestions — UNVERIFIED</h2>']
    parts += ['<p>' + _esc(s['label'] + ': ' + s['url']) + '</p>' for s in inv.suggestions]
    parts += ['<h2>Heuristic exposure assessment</h2><p>' + _esc(inv.risk) + '</p>', '<h2>Timeline</h2>']
    parts += ['<p>' + _esc(e.timestamp + ': ' + e.description) + '</p>' for e in inv.timeline]
    parts += ['<h2>AI-selected follow-up actions</h2>'] + ['<p>' + _esc(r) + '</p>' for r in inv.ai_recommendations]
    parts += ['<h2>Warnings / limitations</h2>'] + ['<p>' + _esc(w) + '</p>' for w in inv.warnings]
    return '\n'.join(parts) + '</html>'
