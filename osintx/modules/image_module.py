from __future__ import annotations

import hashlib
from pathlib import Path

from core.schema import Entity, EntityType, Investigation, ToolResult
from integrations.registry import get_integration
from modules.base import InvestigationModule
from utils.logger import get_logger

log = get_logger(__name__)


class ImageModule(InvestigationModule):
    target_type = "image"

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        image_path = Path(target)
        if not image_path.exists():
            investigation.warnings.append(f"Image file not found: {target}")
            return

        # EXIF / GPS / camera metadata
        if self.tool_registry.is_available("exiftool"):
            exiftool = get_integration("exiftool", self.tool_registry.path_for("exiftool"), self.timeout)
            investigation.add_tool_result(exiftool.run(str(image_path)))
        else:
            log.warning("exiftool not installed — skipping EXIF extraction for %s", target)

        # OCR via tesseract
        if self.tool_registry.is_available("tesseract"):
            from utils.shell import run_command
            argv = [self.tool_registry.path_for("tesseract"), str(image_path), "stdout"]
            result = run_command(argv, timeout=self.timeout)
            text = (result.stdout or "").strip()
            entities = []
            if text:
                entities.append(Entity(
                    type=EntityType.URL, value="[ocr_text_extracted]", source="tesseract",
                    confidence=0.5, metadata={"ocr_text": text[:5000]},
                ))
            investigation.add_tool_result(ToolResult(
                tool="tesseract", target=target, success=result.ok,
                entities=entities, raw_output=text[:5000],
                error=None if result.ok else result.stderr,
            ))

        # QR code decoding
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode as qr_decode

            img = Image.open(image_path)
            decoded = qr_decode(img)
            qr_entities = [
                Entity(type=EntityType.URL, value=d.data.decode("utf-8", errors="replace"),
                       source="pyzbar", confidence=0.9, metadata={"kind": "qr_code"})
                for d in decoded
            ]
            investigation.add_tool_result(ToolResult(
                tool="pyzbar", target=target, success=True, entities=qr_entities, raw_output="",
            ))
        except Exception as exc:  # noqa: BLE001
            investigation.warnings.append(f"QR decoding skipped: {exc}")

        # Perceptual/cryptographic hash for identity/dedup tracking
        try:
            data = image_path.read_bytes()
            sha256 = hashlib.sha256(data).hexdigest()
            investigation.entities.append(Entity(
                type=EntityType.TECHNOLOGY, value=f"sha256:{sha256}", source="hashing",
                confidence=1.0, metadata={"kind": "file_hash"},
            ))
        except OSError as exc:
            investigation.warnings.append(f"Hashing failed: {exc}")

        # Reverse image search links (generated, not scraped)
        investigation.entities.append(Entity(
            type=EntityType.URL, value="https://images.google.com/searchbyimage?image_url=<upload_manually>",
            source="image_module", confidence=0.2,
            metadata={"kind": "manual_reverse_search", "note": "Upload the image manually; no scraping performed."},
        ))
