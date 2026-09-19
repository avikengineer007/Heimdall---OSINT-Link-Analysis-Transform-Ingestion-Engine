"""
Unit tests for data sanitization and normalization.
"""

import pytest
from heimdall.core.sanitizers import DataSanitizer


def test_domain_sanitization():
    assert DataSanitizer.domain("EXAMPLE.COM") == "example.com"
    assert DataSanitizer.domain("  https://sub.domain.org/path?arg=1#hash ") == "sub.domain.org"
    assert DataSanitizer.domain("target.com.") == "target.com"
    assert DataSanitizer.domain("http://target.com:8080/") == "target.com"
    assert DataSanitizer.domain("invalid_domain..com") is None
    assert DataSanitizer.domain("") is None


def test_ipv4_sanitization():
    assert DataSanitizer.ipv4("192.168.1.1") == "192.168.1.1"
    assert DataSanitizer.ipv4("  10.0.0.1/24 ") == "10.0.0.1"
    assert DataSanitizer.ipv4("999.999.999.999") is None
    assert DataSanitizer.ipv4("invalid-ip") is None
    assert DataSanitizer.ipv4("") is None


def test_ipv6_sanitization():
    assert DataSanitizer.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    assert DataSanitizer.ipv6("[2001:db8::1]:8080") == "2001:db8::1"
    assert DataSanitizer.ipv6("invalid-ipv6") is None


def test_email_sanitization():
    assert DataSanitizer.email("  User.Name+tag@Sub.Example.COM ") == "user.name+tag@sub.example.com"
    assert DataSanitizer.email("not-an-email") is None
    assert DataSanitizer.email("user@domain..com") is None


def test_port_sanitization():
    assert DataSanitizer.port("443") == 443
    assert DataSanitizer.port(80) == 80
    assert DataSanitizer.port(0) is None
    assert DataSanitizer.port(70000) is None
    assert DataSanitizer.port("invalid") is None


def test_asn_sanitization():
    assert DataSanitizer.asn("13335") == "AS13335"
    assert DataSanitizer.asn("as15169") == "AS15169"
    assert DataSanitizer.asn("invalid") is None
