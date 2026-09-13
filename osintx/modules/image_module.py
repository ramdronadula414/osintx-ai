from __future__ import annotations

import hashlib
import json
import warnings
from PIL import Image, ExifTags, UnidentifiedImageError
from core.schema import Entity, EntityType, Investigation, ToolResult, ResultStatus
from modules.base import InvestigationModule
from utils.shell import run_command
from utils.validators import validate_image


class ImageModule(InvestigationModule):
    target_type = 'image'

    def run(self, target: str, investigation: Investigation, **kwargs) -> None:
        target = validate_image(target)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', Image.DecompressionBombWarning)
                with Image.open(target) as image:
                    image.verify()
                with Image.open(target) as image:
                    metadata = dict(image.getexif())
                    if not self.tool_registry.is_available('exiftool'):
                        entities = [Entity(EntityType.METADATA, json.dumps(value, default=str, ensure_ascii=False), 'Pillow',
                                           status=ResultStatus.CONFIRMED, evidence=f'{ExifTags.TAGS.get(key, key)}: {value}',
                                           metadata={'kind': str(ExifTags.TAGS.get(key, key)), 'target': target, 'origin': 'embedded'},
                                           confidence_basis='Embedded EXIF field; authenticity and real-world interpretation unverified')
                                    for key, value in metadata.items()]
                        investigation.add_tool_result(ToolResult('Pillow:EXIF', target, True, entities=entities,
                                                               status=ResultStatus.FOUND if entities else ResultStatus.NOT_FOUND))
                    self._qr(image, target, investigation)
        except (OSError, ValueError, UnidentifiedImageError, Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            investigation.add_tool_result(ToolResult('image', target, False,
                                                   status=ResultStatus.PERMISSION_ERROR if isinstance(exc, PermissionError) else ResultStatus.ERROR,
                                                   error=f'Unable to process image ({type(exc).__name__})'))
            return
        self.run_tool('exiftool', target, investigation, local=True)
        if self.tool_registry.is_available('tesseract'):
            result = run_command([self.tool_registry.path_for('tesseract'), target, 'stdout'], timeout=self.timeout)
            entities = [Entity(EntityType.TEXT, result.stdout.strip(), 'tesseract', status=ResultStatus.UNVERIFIED,
                               evidence='OCR transcription; manually compare with the image', confidence_basis='OCR may misread characters')] if result.ok and result.stdout.strip() else []
            investigation.add_tool_result(ToolResult.from_command('tesseract', target, result, entities))
        else:
            investigation.add_tool_result(ToolResult('tesseract', target, False, status=ResultStatus.TOOL_UNAVAILABLE, error='Optional OCR executable not installed'))
        try:
            digest = hashlib.sha256()
            with open(target, 'rb') as stream:
                for chunk in iter(lambda: stream.read(65536), b''):
                    digest.update(chunk)
            investigation.add_tool_result(ToolResult('hashing', target, True, entities=[
                Entity(EntityType.FILE_HASH, digest.hexdigest(), 'hashing', status=ResultStatus.CONFIRMED,
                       evidence='SHA-256 computed from local file bytes', metadata={'kind': 'sha256', 'target': target},
                       confidence_basis='Deterministic local file hash')]))
        except OSError as exc:
            investigation.add_tool_result(ToolResult('hashing', target, False, status=ResultStatus.PERMISSION_ERROR if isinstance(exc, PermissionError) else ResultStatus.ERROR, error='Unable to read file for hashing'))
        investigation.add_suggestion('Reverse image search: upload manually', 'https://images.google.com/')
        investigation.warnings.append('Metadata may be edited or stale. GPS fields do not verify a real location. No face identification is performed.')

    def _qr(self, image, target, investigation):
        try:
            from pyzbar.pyzbar import decode
        except (ImportError, OSError):
            investigation.add_tool_result(ToolResult('pyzbar', target, False, status=ResultStatus.TOOL_UNAVAILABLE, error='Optional pyzbar/libzbar dependency unavailable'))
            return
        try:
            decoded = decode(image)
            entities = [Entity(EntityType.TEXT, item.data.decode('utf-8', errors='replace'), 'pyzbar',
                               status=ResultStatus.UNVERIFIED, evidence='Barcode decoded from supplied image',
                               metadata={'kind': 'barcode'}, confidence_basis='Decoded text; authenticity and any linked destination are unverified') for item in decoded]
            investigation.add_tool_result(ToolResult('pyzbar', target, True, entities=entities, status=ResultStatus.UNVERIFIED if entities else ResultStatus.NOT_FOUND))
        except Exception as exc:  # Optional native decoder failure must not suppress hashing/EXIF.
            investigation.add_tool_result(ToolResult('pyzbar', target, False, error=f'Barcode decoder failed ({type(exc).__name__})'))
