from __future__ import annotations

import json

from core.schema import Entity, EntityType, ToolResult
from integrations.base import ToolIntegration
from utils.shell import CommandResult


class ExifToolIntegration(ToolIntegration):
    """Wraps ExifTool for EXIF/GPS/camera metadata extraction from images
    the analyst has locally — never fetched from a remote profile."""
    name = "exiftool"

    def build_argv(self, target: str, **kwargs) -> list[str]:
        return [self.executable_path, "-j", "-n", target]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        entities: list[Entity] = []
        raw = result.stdout or ""
        try:
            data = json.loads(raw)
            record = data[0] if data else {}
        except (json.JSONDecodeError, IndexError):
            record = {}

        gps_lat = record.get("GPSLatitude")
        gps_lon = record.get("GPSLongitude")
        if gps_lat is not None and gps_lon is not None:
            entities.append(Entity(
                type=EntityType.URL,
                value=f"https://www.google.com/maps?q={gps_lat},{gps_lon}",
                source="exiftool",
                confidence=0.9,
                metadata={"kind": "gps_location", "lat": gps_lat, "lon": gps_lon},
            ))

        camera_make = record.get("Make")
        camera_model = record.get("Model")
        if camera_make or camera_model:
            entities.append(Entity(
                type=EntityType.TECHNOLOGY,
                value=f"{camera_make or ''} {camera_model or ''}".strip(),
                source="exiftool",
                confidence=0.9,
                metadata={"kind": "camera"},
            ))

        return ToolResult(
            tool=self.name, target=target, success=result.ok,
            entities=entities, raw_output=raw[:20000],
            error=None if result.ok else result.stderr,
        )
