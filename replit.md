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
    - **Subdomain Discovery**: Combines Certificate Transparency logs (`crt.sh`) and DNS probing of ~290 common service names. Runs in parallel and attributes sources. For large domains (100+ subdomains), curates the display set by security relevance: well-known service names (mail, vpn, api, sso, admin, etc.), DNS-resolving hosts, and highest certificate activity are prioritized. CNAME enrichment runs only on the curated display set for performance. Accurate total counts are always disclosed.
    - **CNAME Provider Identification**: Resolves CNAME chains for all discovered subdomains (up to 8 hops, loop-safe) and maps targets to 160+ known SaaS/cloud providers (Shopify, Zendesk, HubSpot, AWS, Azure, Cloudflare, Akamai, etc.) across categories (E-commerce, CDN, Cloud, Marketing, Support, CRM, Identity, Monitoring, etc.). Results shown with provider badges, category labels, and CNAME chain tooltips.
    - **Null MX and No-Mail Domain Detection**: Recognizes `MX 0 .` (RFC 7505) to classify non-mail domains.
    - **DANE/TLSA Analysis**: Queries and parses TLSA records for MX hosts, integrated into posture scoring, with educational context on adoption and complementarity with MTA-STS.
    - **DMARCbis Readiness**: Detects and displays `np=`, `t=`, and `psd=` tags, raising educational issues for missing `np=` on enforcing domains.
    - **MPIC Awareness**: CAA analysis includes context on Multi-Perspective Issuance Corroboration (CA/B Forum Ballot SC-067).
    - **Subdomain-aware analysis**: Handles DNSSEC inheritance, NS delegation, and RDAP lookups for subdomains, providing context-aware messaging when analyzing a subdomain.
- **Data Model**: `DomainAnalysis` stores all results including DNS records, SPF/DMARC status, and policies in JSON fields.

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