"""
Heimdall Transform Subsystem.
Imports all built-in transforms to ensure automatic registration.
"""

from heimdall.transforms.base import BaseTransform
from heimdall.transforms.registry import TransformRegistry, register_transform

# Phase 1 — Core transforms
from heimdall.transforms.dns_doh import DNSResolutionTransform, ReverseDNSTransform
from heimdall.transforms.crtsh import CrtshSubdomainTransform
from heimdall.transforms.whois_rdap import DomainRDAPTransform, IPV4RDAPTransform
from heimdall.transforms.shodan import ShodanInternetDBTransform, ShodanHostEnrichmentTransform
from heimdall.transforms.web_surface import WebSurfaceTransform

# Phase 3 — Advanced Intelligence transforms
from heimdall.transforms.virustotal import VirusTotalTransform
from heimdall.transforms.bgp_routing import BGPRoutingTransform
from heimdall.transforms.abuse_ipdb import AbuseIPDBTransform
from heimdall.transforms.reverse_whois import ReverseWhoisTransform
from heimdall.transforms.mx_security import MXSecurityTransform

# Phase 5 — Active Recon & Plugin SDK
from heimdall.transforms.sdk import heimdall_plugin
from heimdall.transforms.tls_cert_extract import TLSCertExtractTransform
from heimdall.transforms.banner_grab import BannerGrabTransform
from heimdall.transforms.http_security_audit import HTTPSecurityAuditTransform

# Enterprise Recon & Threat Intelligence Transforms
from heimdall.transforms.takeover import SubdomainTakeoverTransform
from heimdall.transforms.cloud_buckets import CloudBucketHunterTransform
from heimdall.transforms.historical import HistoricalReconTransform
from heimdall.transforms.exposure_probe import ExposureProbeTransform

__all__ = [
    "BaseTransform",
    "TransformRegistry",
    "register_transform",
    "heimdall_plugin",
    # Phase 1
    "DNSResolutionTransform",
    "ReverseDNSTransform",
    "CrtshSubdomainTransform",
    "DomainRDAPTransform",
    "IPV4RDAPTransform",
    "ShodanInternetDBTransform",
    "ShodanHostEnrichmentTransform",
    "WebSurfaceTransform",
    # Phase 3
    "VirusTotalTransform",
    "BGPRoutingTransform",
    "AbuseIPDBTransform",
    "ReverseWhoisTransform",
    "MXSecurityTransform",
    # Phase 5
    "TLSCertExtractTransform",
    "BannerGrabTransform",
    "HTTPSecurityAuditTransform",
    # Enterprise
    "SubdomainTakeoverTransform",
    "CloudBucketHunterTransform",
    "HistoricalReconTransform",
    "ExposureProbeTransform",
]

