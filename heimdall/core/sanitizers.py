"""
Data Sanitization, Normalization, and Canonicalization Routines.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional


class DataSanitizer:
    """Deterministic normalization pipeline for OSINT entities."""

    _DOMAIN_REGEX = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    _EMAIL_REGEX = re.compile(
        r"^[a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )

    @classmethod
    def domain(cls, value: str) -> Optional[str]:
        """
        Normalizes a domain name:
        - strips scheme, userinfo, paths, ports, leading/trailing whitespace
        - lowercases
        - converts IDN to punycode/ascii if needed
        - strips trailing dots
        """
        if not value:
            return None
        cleaned = value.strip().lower()
        cleaned = re.sub(r"^[a-zA-Z]+://", "", cleaned)
        cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
        if "@" in cleaned:
            cleaned = cleaned.split("@")[-1]
        if ":" in cleaned:
            cleaned = cleaned.split(":")[0]
        if cleaned.endswith("."):
            cleaned = cleaned[:-1]

        try:
            cleaned = cleaned.encode("idna").decode("ascii")
        except Exception:
            pass

        if cls._DOMAIN_REGEX.match(cleaned):
            return cleaned
        return None

    @classmethod
    def ipv4(cls, value: str) -> Optional[str]:
        """
        Sanitizes and normalizes an IPv4 address:
        - strips CIDR notation (e.g., 192.168.1.1/24 -> 192.168.1.1)
        - validates using ipaddress.IPv4Address
        """
        if not value:
            return None
        cleaned = value.strip().split("/")[0]
        try:
            ip_obj = ipaddress.IPv4Address(cleaned)
            return str(ip_obj)
        except ValueError:
            return None

    @classmethod
    def ipv6(cls, value: str) -> Optional[str]:
        """
        Sanitizes and normalizes an IPv6 address:
        - strips brackets, ports, CIDRs, validates via ipaddress.IPv6Address
        """
        if not value:
            return None
        cleaned = value.strip().split("/")[0]
        m = re.match(r"^\[([a-fA-F0-9:]+)\](?::\d+)?$", cleaned)
        if m:
            cleaned = m.group(1)
        else:
            cleaned = cleaned.strip("[]")
        try:
            ip_obj = ipaddress.IPv6Address(cleaned)
            return str(ip_obj)
        except ValueError:
            return None

    @classmethod
    def email(cls, value: str) -> Optional[str]:
        """
        Sanitizes and normalizes an email address.
        """
        if not value:
            return None
        cleaned = value.strip().lower()
        if cls._EMAIL_REGEX.match(cleaned):
            return cleaned
        return None

    @classmethod
    def port(cls, value: int | str) -> Optional[int]:
        """Validates a TCP/UDP port number (1-65535)."""
        try:
            p = int(value)
            if 1 <= p <= 65535:
                return p
        except (ValueError, TypeError):
            pass
        return None

    @classmethod
    def asn(cls, value: int | str) -> Optional[str]:
        """Normalizes ASN string representation (e.g. 'AS13335')."""
        if not value:
            return None
        cleaned = str(value).strip().upper()
        if cleaned.startswith("AS"):
            num_part = cleaned[2:]
        else:
            num_part = cleaned
        if num_part.isdigit():
            return f"AS{num_part}"
        return None

    @classmethod
    def make_urn(cls, entity_type: str, value: str) -> str:
        """Constructs a deterministic canonical URN."""
        return f"{entity_type}:{value.strip()}"
