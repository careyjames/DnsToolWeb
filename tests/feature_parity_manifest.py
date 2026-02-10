"""
Feature Parity Manifest — DNS Tool

Exhaustive enumeration of every analysis feature, detection method, and
capability that MUST exist in both the Python and Go implementations.

Each entry has:
  - feature: Short name
  - category: Grouping (analysis, detection, infrastructure, ui)
  - description: What it does
  - schema_key: The top-level results key it populates
  - detection_methods: Specific techniques used (for detection features)
  - rfc: Governing RFC (if applicable)

This manifest is tested by TestFeatureParityManifest in test_golden.py
to ensure nothing is silently dropped during migration.
"""

FEATURE_PARITY_MANIFEST = [
    {
        "feature": "SPF Analysis",
        "category": "analysis",
        "description": "Parse and validate SPF records, count DNS lookups, detect mechanisms",
        "schema_key": "spf_analysis",
        "detection_methods": ["TXT record lookup", "SPF mechanism parsing", "DNS lookup counting", "include chain resolution"],
        "rfc": "RFC 7208",
    },
    {
        "feature": "DMARC Analysis",
        "category": "analysis",
        "description": "Parse DMARC policy, extract rua/ruf, validate alignment",
        "schema_key": "dmarc_analysis",
        "detection_methods": ["_dmarc TXT lookup", "policy parsing", "rua/ruf URI extraction", "pct validation", "subdomain policy"],
        "rfc": "RFC 7489",
    },
    {
        "feature": "DKIM Analysis",
        "category": "analysis",
        "description": "Discover DKIM selectors, validate key records, detect test mode",
        "schema_key": "dkim_analysis",
        "detection_methods": [
            "Common selector probing (30+ selectors)",
            "Provider-specific selector detection",
            "Key record parsing (v, k, p, t flags)",
            "Test mode (t=y) detection",
            "Key size extraction",
        ],
        "rfc": "RFC 6376",
    },
    {
        "feature": "MTA-STS Analysis",
        "category": "analysis",
        "description": "Check MTA-STS DNS record and fetch/validate policy file",
        "schema_key": "mta_sts_analysis",
        "detection_methods": [
            "_mta-sts TXT lookup",
            "Policy file HTTPS fetch",
            "version/mode/max_age/mx validation",
            "STSv1 version check",
        ],
        "rfc": "RFC 8461",
    },
    {
        "feature": "TLS-RPT Analysis",
        "category": "analysis",
        "description": "Check TLS-RPT DNS record, extract reporting endpoints",
        "schema_key": "tlsrpt_analysis",
        "detection_methods": ["_smtp._tls TXT lookup", "rua extraction (mailto/https)"],
        "rfc": "RFC 8460",
    },
    {
        "feature": "BIMI Analysis",
        "category": "analysis",
        "description": "Check BIMI DNS record, validate SVG logo, check VMC certificate",
        "schema_key": "bimi_analysis",
        "detection_methods": [
            "default._bimi TXT lookup",
            "Logo URL extraction and validation",
            "VMC/authority URL extraction",
            "Logo preview proxy",
        ],
        "rfc": "RFC 9495",
    },
    {
        "feature": "DANE/TLSA Analysis",
        "category": "analysis",
        "description": "Check TLSA records for MX hosts, validate usage/selector/matching",
        "schema_key": "dane_analysis",
        "detection_methods": ["_25._tcp.<mx> TLSA lookup", "Certificate usage parsing", "Selector/matching type validation"],
        "rfc": "RFC 7671",
    },
    {
        "feature": "DNSSEC Analysis",
        "category": "analysis",
        "description": "Check DNSSEC validation status via AD flag, explain trust model",
        "schema_key": "dnssec_analysis",
        "detection_methods": ["AD flag checking via resolver", "DNSKEY record lookup", "DS record presence"],
        "rfc": "RFC 4035",
    },
    {
        "feature": "CAA Analysis",
        "category": "analysis",
        "description": "Check CAA records, separate issue/issuewild/iodef tags",
        "schema_key": "caa_analysis",
        "detection_methods": [
            "CAA record lookup",
            "issue tag parsing",
            "issuewild tag parsing (separate from issue per RFC 8659 §4.3)",
            "iodef notification parsing",
        ],
        "rfc": "RFC 8659",
    },
    {
        "feature": "NS Delegation Analysis",
        "category": "analysis",
        "description": "Compare child vs parent NS records, check delegation consistency",
        "schema_key": "ns_delegation_analysis",
        "detection_methods": ["Authoritative NS query", "Parent zone NS query", "Delegation match comparison"],
        "rfc": "RFC 1034",
    },
    {
        "feature": "Basic DNS Records",
        "category": "infrastructure",
        "description": "Fetch all standard record types (A, AAAA, MX, TXT, NS, CNAME, CAA, SOA, SRV)",
        "schema_key": "basic_records",
        "detection_methods": ["Multi-type DNS query", "TTL extraction"],
    },
    {
        "feature": "Authoritative Records",
        "category": "infrastructure",
        "description": "Query authoritative nameservers directly for ground-truth records",
        "schema_key": "authoritative_records",
        "detection_methods": ["NS record discovery", "Direct authoritative query", "TCP fallback"],
    },
    {
        "feature": "Resolver Consensus",
        "category": "infrastructure",
        "description": "Query multiple public resolvers and compare results for consistency",
        "schema_key": "resolver_consensus",
        "detection_methods": [
            "Cloudflare DNS query",
            "Google Public DNS query",
            "Quad9 query",
            "OpenDNS/Cisco Umbrella query",
            "Cross-resolver comparison",
        ],
    },
    {
        "feature": "Propagation Status",
        "category": "infrastructure",
        "description": "Compare resolver vs authoritative records per type to check propagation sync",
        "schema_key": "propagation_status",
        "detection_methods": ["Per-record-type comparison"],
    },
    {
        "feature": "Registrar/RDAP Lookup",
        "category": "infrastructure",
        "description": "Look up domain registrar, dates, WHOIS server via RDAP",
        "schema_key": "registrar_info",
        "detection_methods": ["IANA RDAP bootstrap", "RDAP HTTP query", "Response caching (24h TTL per RFC 9224)"],
        "rfc": "RFC 9224",
    },
    {
        "feature": "Certificate Transparency Subdomain Discovery",
        "category": "infrastructure",
        "description": "Discover subdomains via CT log queries, classify by certificate status",
        "schema_key": "ct_subdomains",
        "detection_methods": [
            "crt.sh API query",
            "Certificate parsing",
            "Current/expired classification",
            "CNAME resolution for discovered subdomains",
            "Provider summary from CNAME targets",
        ],
        "rfc": "RFC 6962",
    },
    {
        "feature": "DNS Infrastructure Detection",
        "category": "detection",
        "description": "Identify DNS hosting provider, tier, and features from nameservers",
        "schema_key": "dns_infrastructure",
        "detection_methods": [
            "NS hostname matching against known providers",
            "Provider tier classification (enterprise/professional/standard/basic)",
            "Feature detection (DNSSEC support, DDoS protection, anycast, etc.)",
            "Government domain detection",
        ],
    },
    {
        "feature": "Hosting Summary",
        "category": "detection",
        "description": "Identify web hosting, DNS hosting, and email hosting providers",
        "schema_key": "hosting_summary",
        "detection_methods": [
            "A/AAAA record IP-to-provider mapping",
            "NS record provider identification",
            "MX record provider identification",
        ],
    },
    {
        "feature": "Email Security Management Detection",
        "category": "detection",
        "description": "Detect third-party email security management services and monitoring providers",
        "schema_key": "email_security_mgmt",
        "detection_methods": [
            "DMARC rua URI provider matching (30+ monitoring providers)",
            "DMARC ruf URI provider matching",
            "TLS-RPT rua URI provider matching",
            "SPF include flattening provider detection (15+ providers)",
            "Hosted DKIM CNAME chain detection",
            "MTA-STS CNAME hosting detection",
            "Dynamic services NS delegation detection (_dmarc, _domainkey, _mta-sts, _smtp._tls subzones)",
            "CNAME provider mapping (200+ mappings)",
        ],
    },
    {
        "feature": "Mail Posture Classification",
        "category": "detection",
        "description": "Classify domain mail intent (email_enabled, no_mail_verified, etc.)",
        "schema_key": "mail_posture",
        "detection_methods": [
            "MX record presence/absence analysis",
            "Null MX detection (RFC 7505)",
            "SPF -all / v=spf1 -all detection",
            "Signal aggregation (MX, SPF, DMARC, DKIM, MTA-STS presence)",
        ],
    },
    {
        "feature": "Security Posture Assessment",
        "category": "assessment",
        "description": "Evaluate overall domain security posture (STRONG/GOOD/FAIR/WEAK/CRITICAL)",
        "schema_key": "posture",
        "detection_methods": [
            "Protocol state evaluation (SPF+DMARC+DKIM+CAA presence)",
            "DMARC policy strength assessment",
            "Partial pct enforcement detection",
            "Missing rua warning",
            "Provider-aware DKIM credit",
            "Deliberate monitoring detection (p=none with rua)",
        ],
    },
    {
        "feature": "Remediation Engine",
        "category": "assessment",
        "description": "Generate prioritized fix recommendations with DNS examples and RFC references",
        "schema_key": "remediation",
        "detection_methods": [
            "Per-section status evaluation",
            "Severity classification (Critical/High/Medium/Low)",
            "DNS record examples",
            "RFC section references",
            "Top 3 fixes sorted by severity",
            "Achievable posture projection",
        ],
    },
    {
        "feature": "Data Freshness Tracking",
        "category": "infrastructure",
        "description": "Track when each analysis section was last queried",
        "schema_key": "_data_freshness",
        "detection_methods": ["Per-section timestamp tracking"],
    },
    {
        "feature": "Domain Existence Detection",
        "category": "infrastructure",
        "description": "Detect NXDOMAIN, SERVFAIL, undelegated domains",
        "schema_key": "domain_exists",
        "detection_methods": ["SOA/NS query", "NXDOMAIN detection", "Undelegated domain handling"],
    },
    {
        "feature": "Domain Status",
        "category": "infrastructure",
        "description": "Report domain status (active, undelegated, nxdomain) with descriptive message",
        "schema_key": "domain_status",
        "detection_methods": ["DNS response code interpretation"],
    },
    {
        "feature": "Domain Status Message",
        "category": "infrastructure",
        "description": "Human-readable description of domain status",
        "schema_key": "domain_status_message",
        "detection_methods": ["Status message generation"],
    },
    {
        "feature": "Section Status Summary",
        "category": "infrastructure",
        "description": "Per-section pass/fail status summary for quick overview",
        "schema_key": "section_status",
        "detection_methods": ["Per-section status aggregation"],
    },
    {
        "feature": "Authoritative Query Status",
        "category": "infrastructure",
        "description": "Status of direct authoritative nameserver queries",
        "schema_key": "auth_query_status",
        "detection_methods": ["Authoritative query result tracking"],
    },
    {
        "feature": "Resolver TTL",
        "category": "infrastructure",
        "description": "TTL values from public resolver responses",
        "schema_key": "resolver_ttl",
        "detection_methods": ["TTL extraction from resolver responses"],
    },
    {
        "feature": "Authoritative TTL",
        "category": "infrastructure",
        "description": "TTL values from authoritative nameserver responses",
        "schema_key": "auth_ttl",
        "detection_methods": ["TTL extraction from authoritative responses"],
    },
    {
        "feature": "SMTP Transport Analysis",
        "category": "infrastructure",
        "description": "SMTP transport security analysis (STARTTLS, MTA-STS enforcement)",
        "schema_key": "smtp_transport",
        "detection_methods": ["SMTP connection analysis"],
    },
    {
        "feature": "Null MX Detection",
        "category": "detection",
        "description": "Detect null MX record indicating domain does not accept mail",
        "schema_key": "has_null_mx",
        "detection_methods": ["MX record null check (RFC 7505)"],
    },
    {
        "feature": "No-Mail Domain Detection",
        "category": "detection",
        "description": "Determine if domain has declared no-mail intent",
        "schema_key": "is_no_mail_domain",
        "detection_methods": ["Null MX + SPF -all combination detection", "Mail signal aggregation"],
    },
]


REQUIRED_SCHEMA_KEYS = sorted(set(f["schema_key"] for f in FEATURE_PARITY_MANIFEST))


def get_manifest_by_category(category):
    return [f for f in FEATURE_PARITY_MANIFEST if f["category"] == category]


def get_all_detection_methods():
    methods = []
    for f in FEATURE_PARITY_MANIFEST:
        methods.extend(f.get("detection_methods", []))
    return methods


def get_feature_by_schema_key(key):
    for f in FEATURE_PARITY_MANIFEST:
        if f["schema_key"] == key:
            return f
    return None
