from __future__ import annotations

import csv
import io
import json
from core.schema import Investigation


def generate_json(investigation: Investigation) -> str:
    return json.dumps(investigation.to_dict(), indent=2, ensure_ascii=False, default=str)


def generate_csv(inv: Investigation) -> str:
    buffer = io.StringIO(newline='')
    writer = csv.writer(buffer)
    writer.writerow(['record_kind', 'type', 'value', 'source', 'status', 'confidence', 'confidence_basis', 'evidence_or_error', 'metadata'])
    def write(values):
        # Neutralize spreadsheet formulas without modifying stored JSON evidence.
        writer.writerow(["'" + str(v) if str(v).lstrip().startswith(('=', '+', '-', '@', '\t', '\r')) else v for v in values])
    for entity in inv.entities:
        write(['entity', entity.type.value, entity.value, entity.source, entity.status.value, entity.confidence,
               entity.confidence_basis, entity.evidence, json.dumps(entity.metadata, ensure_ascii=False)])
    for result in inv.tool_results:
        write(['source_result', '', result.target, result.tool, result.status.value, '', '', result.error or '', ''])
    for suggestion in inv.suggestions:
        write(['suggestion', '', suggestion['url'], suggestion['label'], 'UNVERIFIED', '', '', 'Generated search suggestion', ''])
    return buffer.getvalue()
