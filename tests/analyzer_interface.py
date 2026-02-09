"""
DNS Analyzer Interface Contract

Defines the formal interface boundary between the DNS analysis engine
and any consuming layer (Flask web app, Go migration, CLI tool, etc.).

This module documents the analysis engine's inputs, outputs, and
injectable dependencies for deterministic testing and future porting.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


ANALYSIS_INPUT_CONTRACT = {
    'domain': {
        'type': 'str',
        'required': True,
        'description': 'Domain name to analyze (e.g., "example.com")',
    },
    'custom_dkim_selectors': {
        'type': 'list[str] | None',
        'required': False,
        'description': 'Optional list of DKIM selectors to check beyond auto-discovered ones',
    },
}

INJECTABLE_DEPENDENCIES = {
    'dns_resolver': {
        'description': 'Custom DNS resolution function. Signature: (record_type: str, domain: str) -> list[str]',
        'default': 'Live DNS queries via dnspython + DoH to Cloudflare/Google/Quad9/OpenDNS',
    },
    'http_client': {
        'description': 'Custom HTTP client function. Signature: (url: str, **kwargs) -> requests.Response',
        'default': 'SSRF-safe requests session with retry logic',
    },
    'skip_network_init': {
        'description': 'Skip IANA RDAP bootstrap data fetch on init (for fast test startup)',
        'default': False,
    },
}

ANALYSIS_METHODS = {
    'analyze_domain': 'Full domain analysis — returns complete results dict',
    'analyze_spf': 'SPF record analysis with RFC 7208 validation',
    'analyze_dmarc': 'DMARC record analysis with RFC 7489 + DMARCbis validation',
    'analyze_dkim': 'DKIM selector discovery and RSA/Ed25519 key validation',
    'analyze_dane': 'DANE/TLSA record analysis per RFC 7672',
    'analyze_dnssec': 'DNSSEC chain validation',
    'analyze_mta_sts': 'MTA-STS policy fetch and validation per RFC 8461',
    'analyze_tlsrpt': 'TLS-RPT record analysis per RFC 8460',
    'analyze_bimi': 'BIMI record and VMC validation',
    'analyze_caa': 'CAA record analysis per RFC 8659',
    'analyze_ns_delegation': 'NS delegation consistency check',
    'get_basic_records': 'Fetch A, AAAA, MX, NS, TXT, CNAME, SOA records',
    'get_authoritative_records': 'Query authoritative nameservers directly',
    'get_registrar_info': 'RDAP/WHOIS/NS-inference registrar lookup',
    'discover_subdomains': 'Certificate Transparency + DNS probe subdomain discovery',
    'validate_resolver_consensus': 'Cross-resolver record comparison',
}

EXTERNAL_IO_DEPENDENCIES = [
    'DNS resolution (dnspython + DoH)',
    'HTTP/HTTPS requests (RDAP, MTA-STS, BIMI, CT logs)',
    'SMTP connections (STARTTLS verification — currently disabled)',
    'Socket resolution (IP validation for SSRF protection)',
]


def create_test_analyzer(**overrides):
    """Create a DNSAnalyzer instance suitable for testing.
    
    Usage:
        analyzer = create_test_analyzer(skip_network_init=True)
        
    For fully deterministic tests with recorded responses:
        analyzer = create_test_analyzer(
            skip_network_init=True,
            dns_resolver=my_recorded_dns_fn,
            http_client=my_recorded_http_fn,
        )
    """
    from dns_analyzer import DNSAnalyzer
    
    defaults = {
        'skip_network_init': True,
    }
    defaults.update(overrides)
    return DNSAnalyzer(**defaults)


def get_interface_version():
    """Return the current interface contract version.
    Bump this when the analyze_domain return structure changes."""
    return 2
