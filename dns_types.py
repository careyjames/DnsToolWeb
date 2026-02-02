"""
Typed dataclasses for DNS Analysis results.
Provides type safety and documentation for analysis output structures.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


@dataclass
class SPFAnalysis:
    """SPF record analysis result."""
    status: str  # 'success', 'warning', 'error'
    message: str
    records: List[str] = field(default_factory=list)
    valid_records: int = 0
    lookup_count: int = 0
    permissiveness: Optional[str] = None  # 'strict', 'moderate', 'permissive'
    issues: List[str] = field(default_factory=list)
    no_mail_intent: bool = False


@dataclass
class DMARCAnalysis:
    """DMARC policy analysis result."""
    status: str  # 'success', 'warning', 'error'
    message: str
    policy: Optional[str] = None  # 'none', 'quarantine', 'reject'
    subdomain_policy: Optional[str] = None
    pct: int = 100
    rua: Optional[str] = None  # Aggregate report URI
    ruf: Optional[str] = None  # Forensic report URI
    issues: List[str] = field(default_factory=list)


@dataclass
class DKIMSelector:
    """DKIM selector key information."""
    selector: str
    found: bool
    key_type: Optional[str] = None
    key_bits: Optional[int] = None
    record: Optional[str] = None


@dataclass
class DKIMAnalysis:
    """DKIM discovery and validation result."""
    status: str  # 'success', 'warning', 'error'
    message: str = ""
    selectors_found: List[DKIMSelector] = field(default_factory=list)
    selectors_checked: List[str] = field(default_factory=list)


@dataclass
class BIMIAnalysis:
    """BIMI record and VMC validation result."""
    status: str  # 'success', 'warning', 'error'
    message: str = ""
    logo_url: Optional[str] = None
    vmc_url: Optional[str] = None
    vmc_valid: bool = False
    vmc_issuer: Optional[str] = None


@dataclass
class CAAAnalysis:
    """CAA record analysis result."""
    status: str  # 'success', 'warning', 'error'
    message: str = ""
    records: List[Dict[str, Any]] = field(default_factory=list)
    issue_allowed: List[str] = field(default_factory=list)
    issuewild_allowed: List[str] = field(default_factory=list)
    iodef_contacts: List[str] = field(default_factory=list)


@dataclass
class DNSSECAnalysis:
    """DNSSEC validation status."""
    status: str  # 'success', 'warning', 'error'
    message: str = ""
    valid: bool = False
    has_ds: bool = False
    has_dnskey: bool = False
    algorithm: Optional[str] = None


@dataclass
class MTASTSAnalysis:
    """MTA-STS policy analysis result."""
    status: str  # 'success', 'warning', 'error'
    message: str = ""
    mode: Optional[str] = None  # 'enforce', 'testing', 'none'
    mx_hosts: List[str] = field(default_factory=list)
    max_age: Optional[int] = None


@dataclass
class TLSRPTAnalysis:
    """TLS-RPT record analysis result."""
    status: str  # 'success', 'warning', 'error'
    message: str = ""
    rua: List[str] = field(default_factory=list)


@dataclass
class RegistrarInfo:
    """RDAP/WHOIS registrar information."""
    status: str  # 'success', 'error'
    source: Optional[str] = None  # 'RDAP', 'WHOIS'
    registrar: Optional[str] = None
    cached: bool = False
    cached_at: Optional[str] = None
    message: Optional[str] = None


@dataclass
class DNSInfrastructure:
    """DNS infrastructure and security provider analysis."""
    provider_tier: str  # 'enterprise', 'standard', 'government'
    provider_name: Optional[str] = None
    is_government: bool = False
    is_self_hosted_enterprise: bool = False
    security_explanation: Optional[str] = None


@dataclass
class SecurityPosture:
    """Overall security posture assessment."""
    state: str  # 'Excellent', 'Good', 'Fair', 'Poor', 'Critical'
    score: int = 0
    color: str = 'secondary'  # Bootstrap color class
    icon: str = 'shield'
    message: str = ""
    issues: List[str] = field(default_factory=list)
    monitoring: List[str] = field(default_factory=list)


@dataclass
class SectionStatus:
    """Status of an individual analysis section."""
    status: str  # 'ok', 'timeout', 'error'
    message: str = ""


@dataclass
class DomainAnalysisResult:
    """Complete domain analysis result.
    
    This is the top-level result structure returned by DNSAnalyzer.analyze_domain().
    It contains all DNS records, email security analysis, and security posture.
    """
    domain_exists: bool
    domain_status: str
    domain_status_message: Optional[str] = None
    
    # Analysis metadata
    section_status: Dict[str, SectionStatus] = field(default_factory=dict)
    
    # DNS Records
    basic_records: Dict[str, List[Any]] = field(default_factory=dict)
    authoritative_records: Dict[str, List[Any]] = field(default_factory=dict)
    propagation_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    
    # Email Security Analysis
    spf_analysis: Optional[SPFAnalysis] = None
    dmarc_analysis: Optional[DMARCAnalysis] = None
    dkim_analysis: Optional[DKIMAnalysis] = None
    mta_sts_analysis: Optional[MTASTSAnalysis] = None
    tlsrpt_analysis: Optional[TLSRPTAnalysis] = None
    bimi_analysis: Optional[BIMIAnalysis] = None
    
    # DNS Security
    caa_analysis: Optional[CAAAnalysis] = None
    dnssec_analysis: Optional[DNSSECAnalysis] = None
    dns_infrastructure: Optional[DNSInfrastructure] = None
    
    # Registry Information
    registrar_info: Optional[RegistrarInfo] = None
    
    # Hosting & Transport
    hosting_summary: Dict[str, str] = field(default_factory=dict)
    smtp_transport: Optional[Dict[str, Any]] = None
    
    # Overall Assessment
    posture: Optional[SecurityPosture] = None
    is_no_mail_domain: bool = False
