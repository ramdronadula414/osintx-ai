from __future__ import annotations

import html
from pathlib import Path
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from core.schema import Investigation
from reports.common import NOTICE, tool_rows, text_sections


def generate_pdf(inv: Investigation, output_path: str) -> str:
    styles = getSampleStyleSheet()
    font_path = Path('/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf')
    if font_path.is_file():
        if 'OSINTXUnicode' not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont('OSINTXUnicode', str(font_path)))
        for style in styles.byName.values():
            style.fontName = 'OSINTXUnicode'
    story = []
    def add(text, style='BodyText'):
        # Split large source fields so a paragraph cannot exceed a page frame.
        text = str(text)
        for start in range(0, max(1, len(text)), 3000):
            safe = html.escape(text[start:start+3000]).replace('\n', '<br/>')
            story.append(Paragraph(safe, styles[style]))
            story.append(Spacer(1, 6))
    add('OSINT-X AI Investigation Report', 'Title')
    for text in (f'ID: {inv.id}', f'Target: {inv.target_type} = {inv.target_value}', f'Started: {inv.started_at}', f'Completed: {inv.completed_at}', NOTICE):
        add(text)
    if not font_path.is_file():
        add('Unicode font unavailable: use JSON/HTML/DOCX for complete non-Latin text.')
    for title, text in text_sections(inv):
        add(title, 'Heading2'); add(text)
    for title, entities in inv.entity_groups():
        add(title, 'Heading2')
        if not entities:
            add('None.')
        for entity in entities:
            add(f'{entity.type.value}: {entity.value}', 'Heading3')
            for text in (f'Status: {entity.status.value}; source: {entity.source}', f'Evidence: {entity.evidence}', f'Confidence basis: {entity.confidence_basis}', f'Metadata: {entity.metadata}'):
                add(text)
    add('Source results / errors / unavailable sources', 'Heading2')
    for row in tool_rows(inv):
        add(' | '.join(row))
    add('Search suggestions — UNVERIFIED', 'Heading2')
    for suggestion in inv.suggestions:
        add(suggestion['label'] + ': ' + suggestion['url'])
    for title, texts in [('Heuristic exposure assessment', [str(inv.risk)]), ('Timeline', [e.timestamp + ': ' + e.description for e in inv.timeline]), ('AI-selected follow-up actions', inv.ai_recommendations), ('Warnings / limitations', inv.warnings)]:
        add(title, 'Heading2')
        for text in texts:
            add(text)
    SimpleDocTemplate(output_path, pagesize=LETTER).build(story)
    return output_path
