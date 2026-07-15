from __future__ import annotations

from pathlib import Path

from core.schema import Investigation
from reports.data_report import generate_csv, generate_json
from reports.docx_report import generate_docx
from reports.html_report import generate_html
from reports.markdown_report import generate_markdown
from reports.pdf_report import generate_pdf


def generate_reports(investigation: Investigation, output_dir: str, formats: list[str]) -> dict[str, str]:
    """Write every requested format to output_dir and return a dict of
    {format: file_path}."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    base_name = f"osintx_{investigation.target_type}_{investigation.id}"
    written: dict[str, str] = {}

    if "markdown" in formats:
        path = out_dir / f"{base_name}.md"
        path.write_text(generate_markdown(investigation))
        written["markdown"] = str(path)

    if "json" in formats:
        path = out_dir / f"{base_name}.json"
        path.write_text(generate_json(investigation))
        written["json"] = str(path)

    if "csv" in formats:
        path = out_dir / f"{base_name}.csv"
        path.write_text(generate_csv(investigation))
        written["csv"] = str(path)

    if "html" in formats:
        path = out_dir / f"{base_name}.html"
        path.write_text(generate_html(investigation))
        written["html"] = str(path)

    if "docx" in formats:
        path = out_dir / f"{base_name}.docx"
        generate_docx(investigation, str(path))
        written["docx"] = str(path)

    if "pdf" in formats:
        path = out_dir / f"{base_name}.pdf"
        generate_pdf(investigation, str(path))
        written["pdf"] = str(path)

    return written
