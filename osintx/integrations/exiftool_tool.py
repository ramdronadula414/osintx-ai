from __future__ import annotations

import json
from core.schema import Entity, EntityType, ToolResult, ResultStatus
from integrations.base import ToolIntegration
from utils.shell import CommandResult
from utils.validators import validate_image


class ExifToolIntegration(ToolIntegration):
    name = 'exiftool'

    def build_argv(self, target: str, **kwargs) -> list[str]:
        return [self.executable_path, '-j', '-n', '-G1', '--', validate_image(target)]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        if not result.ok:
            return ToolResult.from_command(self.name, target, result)
        try:
            data = json.loads(result.stdout)
            if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
                raise ValueError
            record = data[0]
            if any(k.split(':')[-1] == 'Error' for k in record):
                raise ValueError
        except (ValueError, TypeError):
            return ToolResult(self.name, target, False, raw_output=result.stdout, status=ResultStatus.ERROR, error='Invalid ExifTool JSON or file error')
        entities = []
        for key, value in record.items():
            if key == 'SourceFile' or key.startswith(('System:', 'File:', 'ExifTool:')):
                continue
            entities.append(Entity(EntityType.METADATA, json.dumps(value, ensure_ascii=False), self.name,
                                   status=ResultStatus.CONFIRMED, evidence=f'{key}: {value}',
                                   metadata={'kind': key, 'target': target, 'origin': 'computed' if key.startswith('Composite:') else 'embedded'},
                                   confidence_basis='Metadata value extracted from this file; authenticity, capture date, and actual location are not verified'))
        return ToolResult(self.name, target, True, entities=entities, raw_output=result.stdout,
                          status=ResultStatus.FOUND if entities else ResultStatus.NOT_FOUND)
