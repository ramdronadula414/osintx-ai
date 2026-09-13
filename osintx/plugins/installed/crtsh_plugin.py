"""Certificate-log observations are historical candidates, not live DNS proof."""
from __future__ import annotations

from core.schema import Entity, EntityType, ToolResult, ResultStatus
from plugins.base import OsintxPlugin, PluginMetadata
from utils.http import request_json, SourceError
from utils.validators import validate_domain, ValidationError


class CrtShPlugin(OsintxPlugin):
    metadata = PluginMetadata('crt.sh Certificate Transparency', '1.1.0', 'OSINT-X AI Team',
                              'Historical names observed in public certificate logs', ['domain'])

    def is_available(self) -> bool:
        return True  # No preflight: the actual lookup records HTTP/network failures explicitly.

    def run(self, target: str, target_type: str, **kwargs) -> ToolResult:
        target = validate_domain(target)
        entities = []
        try:
            records = request_json('GET', 'https://crt.sh/', params={'q': f'%.{target}', 'output': 'json'}, timeout=kwargs.get('timeout', 15))
            if not isinstance(records, list) or any(not isinstance(r, dict) or not isinstance(r.get('name_value'), str) for r in records):
                raise SourceError(ResultStatus.API_ERROR, 'Unexpected certificate-log response shape')
            seen = set()
            for record in records:
                for raw_name in record['name_value'].splitlines():
                    wildcard = raw_name.strip().startswith('*.')
                    try:
                        name = validate_domain(raw_name.strip().removeprefix('*.'))
                    except ValidationError:
                        continue
                    if (name != target and not name.endswith('.' + target)) or (name, wildcard) in seen:
                        continue
                    seen.add((name, wildcard))
                    entities.append(Entity(EntityType.CERTIFICATE if wildcard else EntityType.SUBDOMAIN,
                                           '*.' + name if wildcard else name, 'crt.sh',
                                           evidence=f"Certificate log entry {record.get('id', 'UNKNOWN')}: {raw_name.strip()}",
                                           status=ResultStatus.UNVERIFIED, url='https://crt.sh/',
                                           metadata={'certificate_id': record.get('id'), 'wildcard': wildcard},
                                           confidence_basis='Certificate name observed; current DNS existence and target ownership unverified'))
            return ToolResult('crt.sh', target, True, entities=entities, status=ResultStatus.UNVERIFIED if entities else ResultStatus.NOT_FOUND)
        except SourceError as exc:
            return ToolResult('crt.sh', target, False, status=exc.status if exc.status != ResultStatus.NOT_FOUND else ResultStatus.API_ERROR, error=str(exc))
