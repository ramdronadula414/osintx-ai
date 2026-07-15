import pytest

from utils.validators import (
    ValidationError, validate_domain, validate_email, validate_ip,
    validate_name, validate_phone, validate_username, is_private_ip,
)


def test_validate_email_ok():
    assert validate_email("user@example.com") == "user@example.com"


def test_validate_email_rejects_injection():
    with pytest.raises(ValidationError):
        validate_email("user@example.com; rm -rf /")


def test_validate_domain_ok():
    assert validate_domain("Example.COM.") == "example.com"


def test_validate_domain_rejects_bad_chars():
    with pytest.raises(ValidationError):
        validate_domain("example.com && whoami")


def test_validate_ip_ok():
    assert validate_ip("8.8.8.8") == "8.8.8.8"


def test_validate_ip_rejects_bad_value():
    with pytest.raises(ValidationError):
        validate_ip("not-an-ip")


def test_validate_username_rejects_shell_metacharacters():
    with pytest.raises(ValidationError):
        validate_username("user`id`")


def test_validate_username_ok():
    assert validate_username("john_doe-99") == "john_doe-99"


def test_validate_phone_ok():
    assert validate_phone("+1 (555) 123-4567") == "+1 (555) 123-4567"


def test_validate_name_ok():
    assert validate_name("John O'Doe-Smith") == "John O'Doe-Smith"


def test_validate_name_rejects_special_chars():
    with pytest.raises(ValidationError):
        validate_name("John; DROP TABLE users;")


def test_is_private_ip():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("8.8.8.8") is False
