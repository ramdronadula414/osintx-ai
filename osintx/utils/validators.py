"""Validate targets before any command, DNS query, or HTTP request."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


class ValidationError(ValueError):
    pass


def _text(value: str, maximum: int = 253) -> str:
    if not isinstance(value, str) or any(unicodedata.category(c).startswith('C') for c in value):
        raise ValidationError('Target must be text without control characters')
    value = value.strip()
    if not value or len(value) > maximum:
        raise ValidationError(f'Target must contain 1–{maximum} characters')
    return value


def validate_domain(value: str) -> str:
    value = _text(value).removesuffix('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
        ipaddress.ip_address(value)
    except UnicodeError as exc:
        raise ValidationError('Invalid international domain name') from exc
    except ValueError:
        pass
    else:
        raise ValidationError('Use --ip for an IP address')
    if len(value) > 253 or not re.fullmatch(r'(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+', value):
        raise ValidationError('Invalid domain; provide a hostname without a URL, path, or port')
    if value.rsplit('.', 1)[1].isdigit():
        raise ValidationError('Domain suffix must not be numeric')
    return value


def validate_dns_name(value: str) -> str:
    value = _text(value).lower().removesuffix('.')
    if value.startswith('_dmarc.'):
        return '_dmarc.' + validate_domain(value[7:])
    if value.endswith('.in-addr.arpa') or value.endswith('.ip6.arpa'):
        if re.fullmatch(r'[a-f0-9.]+\.(?:in-addr|ip6)\.arpa', value):
            return value
    return validate_domain(value)


def validate_email(value: str) -> str:
    value = _text(value, 254)
    if value.count('@') != 1:
        raise ValidationError('Invalid email address')
    local, domain = value.split('@')
    if (not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}", local)
            or local.startswith('.') or local.endswith('.') or '..' in local):
        raise ValidationError('Invalid email local part')
    return local + '@' + validate_domain(domain)


def validate_ip(value: str) -> str:
    value = _text(value)
    if '%' in value:
        raise ValidationError('Scoped IPv6 addresses are not supported')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValidationError('Invalid IPv4/IPv6 address') from exc


def validate_username(value: str) -> str:
    value = _text(value, 64)
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', value):
        raise ValidationError('Username must start with a letter, digit, or underscore; use letters, digits, dot, underscore, or hyphen')
    return value


def validate_phone(value: str) -> str:
    value = _text(value, 30)
    if not re.fullmatch(r'\+?[0-9() -]+', value) or not 6 <= sum(c.isdigit() for c in value) <= 15:
        raise ValidationError('Invalid phone syntax (number ownership/existence is not checked)')
    return value


def validate_name(value: str) -> str:
    value = _text(value, 100)
    if len(value) < 2 or not any(c.isalpha() for c in value) or any(not (unicodedata.category(c)[0] in 'LM' or c in " '-.") for c in value):
        raise ValidationError('Invalid person name')
    return value


def validate_company(value: str) -> str:
    value = _text(value, 160)
    if not any(c.isalnum() for c in value):
        raise ValidationError('Company name must contain letters or digits')
    return value


def validate_image(value: str) -> str:
    path = Path(_text(value, 4096)).expanduser().resolve()
    if not path.is_file():
        raise ValidationError('Image target must be an existing regular file')
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValidationError('Image exceeds the 100 MiB processing limit')
    return str(path)


def validate_url(value: str) -> str:
    value = _text(value, 8192)
    try:
        parts = urlsplit(value)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or any(c.isspace() for c in value) or '\\' in value:
            raise ValueError
        port = parts.port
        try:
            host = str(ipaddress.ip_address(parts.hostname))
            host = f'[{host}]' if ':' in host else host
        except ValueError:
            host = validate_domain(parts.hostname)
        authority = host + (f':{port}' if port and (parts.scheme, port) not in [('http', 80), ('https', 443)] else '')
        return urlunsplit((parts.scheme.lower(), authority, parts.path or '/', parts.query, ''))
    except ValueError as exc:
        raise ValidationError('Invalid HTTP(S) URL') from exc


def is_private_ip(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def validate_target(kind: str, value: str) -> str:
    validators = {'person': validate_name, 'company': validate_company, 'username': validate_username,
                  'email': validate_email, 'domain': validate_domain, 'ip': validate_ip, 'image': validate_image}
    if kind not in validators:
        raise ValidationError(f'Unsupported target type: {kind}')
    return validators[kind](value)
