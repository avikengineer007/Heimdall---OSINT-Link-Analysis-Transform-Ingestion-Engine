"""
Deterministic Graph Schema Contract & Data Models for Heimdall.
"""

from __future__ import annotations

import enum
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field, field_validator


class EntityType(str, enum.Enum):
    """Canonical OSINT Entity Types."""
    DOMAIN = "Domain"
    SUBDOMAIN = "Subdomain"
    IPV4 = "IPv4"
    IPV6 = "IPv6"
    PORT_SERVICE = "PortService"
    ORGANIZATION = "Organization"
    REGISTRAR = "Registrar"
    EMAIL = "Email"
    ASN = "ASNumber"
    URL = "URL"
    SSL_CERTIFICATE = "SSLCertificate"
    PERSON = "Person"
    # Phase 3 — Advanced Intelligence
    CIDR_BLOCK = "CIDRBlock"
    THREAT_SCORE = "ThreatScore"
    DMARC_POLICY = "DMARCPolicy"
    ABUSE_REPORT = "AbuseReport"
    MALICIOUS_DETECTION = "MaliciousDetection"
    INTERNET_EXCHANGE = "InternetExchange"
    SPF_RECORD = "SPFRecord"
    DKIM_SELECTOR = "DKIMSelector"
    MX_SERVER = "MXServer"
    CVE = "CVE"
    # Phase 5 — Active Recon & Automation
    SERVICE_BANNER = "ServiceBanner"
    SECURITY_HEADER = "SecurityHeader"
    WAF_SIGNATURE = "WAFSignature"
    TLS_CERTIFICATE = "TLSCertificate"  # Active (vs passive crtsh)
    MONITORING_SCHEDULE = "MonitoringSchedule"


class GraphNode(BaseModel):
    """Normalized graph node entity."""
    urn: str = Field(..., description="Canonical URN: '<Type>:<Value>'")
    entity_type: str = Field(..., description="Entity type identifier")
    value: str = Field(..., description="Canonical entity value")
    properties: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("urn")
    @classmethod
    def validate_urn(cls, v: str) -> str:
        if ":" not in v:
            raise ValueError(f"URN must follow '<Type>:<Value>' format, received '{v}'")
        return v

    @classmethod
    def from_urn(cls, urn: str, properties: Optional[Dict[str, Any]] = None) -> GraphNode:
        parts = urn.split(":", 1)
        return cls(
            urn=urn,
            entity_type=parts[0],
            value=parts[1],
            properties=properties or {},
        )


class GraphEdge(BaseModel):
    """
    Strict Graph Schema Contract:
    {"source": "<type:value>", "target": "<type:value>", "target_type": "<Type>", "rel": "<RELATION_NAME>", "properties": {}}
    """
    source: str = Field(..., description="Source node as <type:value>")
    target: str = Field(..., description="Target node as <type:value>")
    target_type: str = Field(..., description="Target node type")
    rel: str = Field(..., description="Directed relationship identifier, e.g. RESOLVES_TO")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Edge property map")

    @field_validator("source", "target")
    @classmethod
    def validate_node_format(cls, v: str) -> str:
        if ":" not in v:
            raise ValueError(f"Node identifier must be in '<Type>:<Value>' format, received: '{v}'")
        parts = v.split(":", 1)
        if not parts[0] or not parts[1]:
            raise ValueError(f"Node identifier '{v}' cannot have empty type or value")
        return v

    @property
    def edge_key(self) -> Tuple[str, str, str]:
        """Unique deterministic edge identity tuple."""
        return (self.source, self.rel, self.target)

    @property
    def hash_id(self) -> str:
        """Deterministic sha256 hash representing this edge."""
        raw = f"{self.source}|{self.rel}|{self.target}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_contract_dict(self) -> Dict[str, Any]:
        """Emits the exact schema contract dictionary."""
        return {
            "source": self.source,
            "target": self.target,
            "target_type": self.target_type,
            "rel": self.rel,
            "properties": self.properties,
        }


class TransformResult(BaseModel):
    """Execution telemetry and extracted edges from a single transform execution."""
    transform_name: str
    input_entity: str
    status: str = "SUCCESS"  # SUCCESS, PARTIAL, FAILED
    edges: List[GraphEdge] = Field(default_factory=list)
    duration_ms: float = 0.0
    error_message: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InvestigationSession(BaseModel):
    """Tracks an ongoing multi-hop investigation."""
    session_id: str
    seed_urn: str
    max_depth: int = 2
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    total_nodes: int = 0
    total_edges: int = 0
    visited_urns: Set[str] = Field(default_factory=set)
