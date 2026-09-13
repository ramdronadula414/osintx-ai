"""DNS fallback when the optional dig executable is unavailable."""
import dns.exception
import dns.resolver
from core.schema import ToolResult, ResultStatus
from integrations.dig_tool import dns_entity
from utils.validators import validate_dns_name


def lookup(target: str, record_type: str, timeout: float = 15) -> ToolResult:
    target = validate_dns_name(target)
    tool = f'dnspython:{record_type}'
    try:
        resolver = dns.resolver.Resolver()
        answer = resolver.resolve(target, record_type, lifetime=timeout, search=False)
        entities = [dns_entity(str(answer.canonical_name), record_type, record.to_text(), 'dnspython') for record in answer]
        return ToolResult(tool, target, True, entities=entities, status=ResultStatus.FOUND if entities else ResultStatus.NOT_FOUND)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ToolResult(tool, target, True, status=ResultStatus.NOT_FOUND)
    except dns.exception.Timeout:
        return ToolResult(tool, target, False, status=ResultStatus.TIMEOUT, error='DNS lookup timed out')
    except (dns.exception.DNSException, OSError):
        return ToolResult(tool, target, False, status=ResultStatus.NETWORK_ERROR, error='DNS resolver unavailable or query failed')
