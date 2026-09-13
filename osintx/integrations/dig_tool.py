from __future__ import annotations

import re
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.exception
from core.schema import Entity, EntityType, ToolResult, ResultStatus
from integrations.base import ToolIntegration
from utils.shell import CommandResult
from utils.validators import validate_dns_name

RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']


def dns_entity(owner: str, rtype: str, value: str, source: str) -> Entity:
    # dnspython validates record syntax, including IPv4/6, MX priority, and complete TXT/SOA data.
    record = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), value)
    normalized = record.to_text()
    return Entity(EntityType.DNS_RECORD, normalized, source, status=ResultStatus.CONFIRMED,
                  evidence=f'{owner} IN {rtype} {normalized}',
                  metadata={'owner': owner.lower().rstrip('.'), 'record': rtype},
                  confidence_basis='Direct DNS response; confirms the record returned, not host ownership or reachability')


class DigIntegration(ToolIntegration):
    name = 'dig'

    def build_argv(self, target: str, record_type: str = 'A', **kwargs) -> list[str]:
        target = validate_dns_name(target)
        if record_type not in RECORD_TYPES + ['PTR']:
            raise ValueError('Unsupported DNS record type')
        return [self.executable_path, '+noall', '+comments', '+answer', '+time=3', '+tries=1', target, record_type]

    def parse(self, target: str, result: CommandResult) -> ToolResult:
        if not result.ok:
            return ToolResult.from_command(self.name, target, result)
        text = result.stdout
        match = re.search(r'status:\s*([A-Z]+)', text)
        if match and match[1] != 'NOERROR':
            status = {'NXDOMAIN': ResultStatus.NOT_FOUND, 'REFUSED': ResultStatus.PERMISSION_ERROR,
                      'SERVFAIL': ResultStatus.NETWORK_ERROR}.get(match[1], ResultStatus.ERROR)
            return ToolResult(self.name, target, status == ResultStatus.NOT_FOUND, raw_output=text,
                              status=status, error=None if status == ResultStatus.NOT_FOUND else f'DNS {match[1]}')
        entities = []
        malformed = False
        for line in text.splitlines():
            if not line.strip() or line.startswith(';'):
                continue
            parts = line.split(None, 4)
            if len(parts) != 5 or parts[2] != 'IN' or not parts[1].isdigit():
                malformed = True
                continue
            try:
                entities.append(dns_entity(parts[0], parts[3], parts[4], self.name))
            except (dns.exception.DNSException, ValueError):
                malformed = True
        if malformed:
            return ToolResult(self.name, target, False, raw_output=text, error='Malformed DNS answer', status=ResultStatus.ERROR)
        status = ResultStatus.FOUND if entities else ResultStatus.NOT_FOUND if match else ResultStatus.UNKNOWN
        return ToolResult(self.name, target, True, entities=entities, raw_output=text, status=status)

    def run_all_record_types(self, target: str) -> list[ToolResult]:
        results = []
        for rtype in RECORD_TYPES:
            result = self.run(target, record_type=rtype)
            result.tool = f'dig:{rtype}'
            results.append(result)
        return results
