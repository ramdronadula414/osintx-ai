from __future__ import annotations

import importlib
from pathlib import Path
from core.schema import Investigation
from utils.validators import ValidationError

GENERATORS = {'markdown': ('markdown_report', 'generate_markdown', 'md'),
              'json': ('data_report', 'generate_json', 'json'), 'csv': ('data_report', 'generate_csv', 'csv'),
              'html': ('html_report', 'generate_html', 'html'), 'docx': ('docx_report', 'generate_docx', 'docx'),
              'pdf': ('pdf_report', 'generate_pdf', 'pdf')}


def validate_formats(formats: list[str]) -> list[str]:
    values = list(dict.fromkeys(f.strip().lower() for f in formats))
    if not values or any(value not in GENERATORS for value in values):
        raise ValidationError('Report formats must be a nonempty subset of markdown,json,csv,html,docx,pdf')
    return values


def generate_reports(investigation: Investigation, output_dir: str, formats: list[str]) -> dict[str, str]:
    formats = validate_formats(formats)
    out_dir = Path(output_dir).expanduser()
    written = {}
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        investigation.warnings.append(f'Reports unavailable: cannot create output directory ({type(exc).__name__})')
        return written
    # Render JSON last so it captures failures in any other report format.
    for fmt in sorted(formats, key=lambda item: item == 'json'):
        module, function, ext = GENERATORS[fmt]
        path = out_dir / f'osintx_{investigation.target_type}_{investigation.id}.{ext}'
        temp = path.with_suffix(path.suffix + '.tmp')
        try:
            generate = getattr(importlib.import_module('reports.' + module), function)
            if fmt in ('docx', 'pdf'):
                generate(investigation, str(temp))
            else:
                temp.write_text(generate(investigation), encoding='utf-8')
            temp.replace(path)
            written[fmt] = str(path)
        except Exception as exc:  # Independent optional renderer boundary; preserve all other formats.
            investigation.warnings.append(f'{fmt} report failed ({type(exc).__name__}); check optional dependency and output permissions')
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                investigation.warnings.append(f'Could not remove partial {fmt} report')
    return written
