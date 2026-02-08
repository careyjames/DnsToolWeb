# DNS Tool — Domain Security Audit

## Overview

The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records like SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, and CAA, with automatic subdomain discovery via Certificate Transparency logs and DNS probing. The tool aims to be an educational authority, ensuring every result is accurate, cited with RFC references, and verifiable. Its core purpose is to elevate domain security posture by providing actionable insights and clear, graduated assessments rather than simple pass/fail verdicts. The project prioritizes accuracy, security, and robust architectural foundations to deliver a reliable and educational service.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Framework
- **Flask**: Web framework.
- **SQLAlchemy**: ORM for database interactions.
- **PostgreSQL**: Primary database.

### Core Components
- **Application Entry Points**: `main.py` (simple entry) and `app.py` (Flask configuration, models, routes).
- **DNS Analysis Engine (`dns_analyzer.py`)**:
    - Utilizes `dnspython` for core DNS logic.
    - Performs domain validation, IDNA encoding, and extensive record queries.
    - Conducts email security analysis (SPF, DMARC, DKIM, DANE/TLSA, MTA-STS, TLS-RPT).
    - Employs multiple external DNS resolvers (Cloudflare, Google, Quad9, OpenDNS) for consensus.
    - Fetches IANA RDAP data.
    - Implements SMTP Transport Verification (STARTTLS, TLS version, cipher strength, certificate validity).
    - Identifies enterprise DNS providers and performs comprehensive DKIM analysis.
    - Detects DMARC monitoring, TLS-RPT reporting, and SPF flattening services.
    - **DNS Evidence Diff**: Compares resolver and authoritative records for various types (A, AAAA, MX, TXT, NS, CAA, SOA, _dmarc, _mta-sts, _smtp._tls).
    - **Subdomain Discovery**: Three cooperative discovery methods feed a unified view: Certificate Transparency logs (`crt.sh`), DNS probing of ~290 common service names, and CNAME chain traversal (intermediate hops within the analyzed domain are extracted as newly discovered subdomains). Runs in parallel and attributes sources. For large domains (100+ subdomains), curates the display set by security relevance: well-known service names (mail, vpn, api, sso, admin, etc.), DNS-resolving hosts, and highest certificate activity are prioritized. CNAME enrichment runs only on the curated display set for performance. Accurate total counts are always disclosed.
    - **CNAME Provider Identification**: Resolves CNAME chains for all discovered subdomains (up to 8 hops, loop-safe) and maps targets to 160+ known SaaS/cloud providers (Shopify, Zendesk, HubSpot, AWS, Azure, Cloudflare, Akamai, etc.) across categories (E-commerce, CDN, Cloud, Marketing, Support, CRM, Identity, Monitoring, etc.). Results shown with provider badges, category labels, and CNAME chain tooltips.
    - **Registrar Lookup Fallback Chain**: Three-tier registrar identification: RDAP (primary) → WHOIS (backup) → NS-based inference (third fallback). Detects restricted WHOIS registries (.es, .br, .kr, .cn, .ru, etc.) and infers registrar from 35+ known NS patterns (Gandi, OVH, GoDaddy, Namecheap, etc.). For subdomains, parent-zone RDAP/WHOIS is tried before NS inference.
    - **Null MX and No-Mail Domain Detection**: Recognizes `MX 0 .` (RFC 7505) to classify non-mail domains.
    - **DANE/TLSA Analysis**: Queries and parses TLSA records for MX hosts, integrated into posture scoring, with educational context on adoption and complementarity with MTA-STS. Provider-aware: detects hosted MX providers (Google Workspace, Microsoft 365, Proton Mail, Fastmail, security gateways) and distinguishes architecturally impossible DANE from deployable DANE. Posture scoring does not penalize domains when their provider can't support DANE. Template shows "Not Available" vs "Not Configured" with provider-specific explanation.
    - **DMARCbis Readiness**: Detects and displays `np=`, `t=`, and `psd=` tags, raising educational issues for missing `np=` on enforcing domains.
    - **MPIC Awareness**: CAA analysis includes context on Multi-Perspective Issuance Corroboration (CA/B Forum Ballot SC-067).
    - **Subdomain-aware analysis**: Handles DNSSEC inheritance, NS delegation, and RDAP lookups for subdomains, providing context-aware messaging when analyzing a subdomain.
- **Data Model**: `DomainAnalysis` stores complete analysis results in a `full_results` JSON column for full history playback. Every stored report contains the complete picture — posture, verdicts, all sections — so historical views are identical to live results. Individual columns (spf_status, dmarc_policy, etc.) are retained for query/filtering but `full_results` is the source of truth for rendering. If `full_results` is missing, the view redirects to re-analyze rather than showing degraded data.
- **Data Integrity Safeguards (v26.10.68)**:
    - `full_results` column has a database-level `NOT NULL` constraint — PostgreSQL will reject any insert without complete data.
    - SQLAlchemy `before_insert` and `before_update` event listeners validate that `full_results` contains all required sections (`basic_records`, `spf_analysis`, `dmarc_analysis`, `dkim_analysis`, `registrar_info`, `posture`) before any write reaches the database.
    - Failed analyses are **never saved** to the database. Only successful, fully-populated reports are persisted. Stats are still tracked for failed attempts.
    - History queries filter to `analysis_success=True AND full_results IS NOT NULL` as an additional safety net.
    - **Schema versioning**: Every `full_results` payload includes a `_schema_version` field (currently `2`). Future code changes can use this to migrate or adapt older records without data loss. Schema changes must always be additive (new fields) — never remove or rename existing fields.
- **Growth & Scalability (v26.10.68)**:
    - Database indexes on `domain`, `ascii_domain`, `created_at`, and composite `(analysis_success, created_at)` for fast queries at scale.
    - **Data export**: `/export/json` streams all analyses as NDJSON (one JSON record per line) for backup, migration, or external processing. Uses paginated streaming to handle any volume without memory issues.
    - **Rendering contract**: `normalize_results()` fills safe defaults for any missing sections before template rendering. Old records from earlier schema versions display correctly even when new analysis sections are added later. Templates never crash on missing keys.
    - **Schema evolution rules**: Only add new fields — never remove or rename existing fields. Use `_schema_version` to gate any version-specific rendering or migration logic.

### Frontend Architecture
- Server-rendered HTML using Jinja2 templates.
- Features a self-hosted Bootstrap dark theme with a native system font stack and subsetted Font Awesome icons.
- Custom CSS and client-side JavaScript for styling and interactivity.
- **PWA Support**: Includes manifest, service worker, and app icons for installability.
- **Pages**: Index (home), Results, History, Statistics.
- **Route Structure**: Standard RESTful routes for analysis, history, and static content (e.g., `/llms.txt` for AI agent guidance).

### Design Patterns
- MVC-style separation.
- Singleton pattern for `DNSAnalyzer`.
- Uses JSON columns in PostgreSQL for flexible data storage.

### Quality of Life & Performance
- Critical inline CSS, preconnect hints, per-IP rate limiting (8 analyses/min via Redis).
- Re-analyze countdown UI and data freshness (live DNS, 6hr RDAP cache).
- SEO optimized with rich schema and meta tags.
- Uses native system fonts and provides optimized rendering for various elements.

## External Dependencies

### Python Packages
- **Flask**: Web framework.
- **Flask-SQLAlchemy**: ORM integration.
- **dnspython**: DNS query library.
- **requests**: HTTP client.
- **idna**: Internationalized domain name encoding.

### External Services
- **Cloudflare DNS (1.1.1.1)**: Consensus resolver.
- **Google Public DNS (8.8.8.8)**: Consensus resolver.
- **Quad9 (9.9.9.9)**: Consensus resolver.
- **OpenDNS/Cisco Umbrella (208.67.222.222)**: Consensus resolver.
- **IANA RDAP**: Registry data lookups.
- **ip-api.com**: Free IP-to-country lookup service.
- **crt.sh**: Certificate Transparency logs for subdomain discovery.

### Database
- **PostgreSQL**: Managed by Replit.