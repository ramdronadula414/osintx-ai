from __future__ import annotations

import csv
import io
import json

from core.schema import Investigation


def generate_json(investigation: Investigation) -> str:
    return json.dumps(investigation.to_dict(), indent=2, default=str)


def generate_csv(investigation: Investigation) -> str:
    """CSV export focuses on the entity table, which is the most
    spreadsheet-friendly part of an investigation."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "source", "confidence", "metadata"])
    for e in investigation.entities:
        writer.writerow([e.type.value, e.value, e.source, e.confidence, json.dumps(e.metadata)])
    return buffer.getvalue()
