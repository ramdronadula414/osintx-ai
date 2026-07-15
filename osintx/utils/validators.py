"""Input validation for every investigation target type.

These guards run before any target string reaches a subprocess argv list,
a DNS resolver, or an HTTP request — rejecting anything that isn't a
syntactically well-formed target of its declared type.
"""
from __future__ import annotations

import ipaddress
import re

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_PHONE_RE = re.compile(r"^\+?[0-9()\-\s]{6,20}$")
# Names: letters (incl. common unicode ranges), spaces, hyphens, apostrophes.
_NAME_RE = re.compile(r"^[A-Za-z\u00C0-\u024F' \-.]{2,100}$")


class ValidationError(ValueError):
    pass


def validate_email(value: str) -> str:
    value = value.strip()
    if not _EMAIL_RE.match(value):
        raise ValidationError(f"'{value}' is not a syntactically valid email address")
    return value


def validate_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if not _DOMAIN_RE.match(value):
        raise ValidationError(f"'{value}' is not a syntactically valid domain")
    return value


def validate_ip(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"'{value}' is not a valid IPv4/IPv6 address") from exc
    return value


def validate_username(value: str) -> str:
    value = value.strip()
    if not _USERNAME_RE.match(value):
        raise ValidationError(
            f"'{value}' contains characters not allowed in a username "
            "(letters, digits, '.', '_', '-' only)"
        )
    return value


def validate_phone(value: str) -> str:
    value = value.strip()
    if not _PHONE_RE.match(value):
        raise ValidationError(f"'{value}' is not a syntactically valid phone number")
    return value


def validate_name(value: str) -> str:
    value = value.strip()
    if not _NAME_RE.match(value):
        raise ValidationError(f"'{value}' contains characters not allowed in a person name")
    return value


def is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False
