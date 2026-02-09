# DNS Tool — Domain Security Audit

## Overview

The DNS Tool is a web-based intelligence platform for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), with automatic subdomain discovery via Certificate Transparency logs and DNS probing. The tool aims to be an educational authority, providing accurate, RFC-cited, and verifiable results. Its core purpose is to elevate domain security by offering actionable insights and graduated assessments, focusing on accuracy, security, and robust architecture.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend
- **Frameworks**: Flask (web), SQLAlchemy (ORM), PostgreSQL (database).
- **DNS Analysis Engine**: Uses `dnspython` for extensive record queries, email security analysis, and DNS evidence diffing. Employs multiple external resolvers for consensus.
- **Subdomain Discovery**: Combines Certificate Transparency logs, DNS probing of common service names, and CNAME chain traversal. Prioritizes security-relevant subdomains for display.
- **CNAME Provider Identification**: Resolves CNAME chains and maps targets to over 160 known SaaS/cloud providers.
- **Registrar Lookup**: Uses a three-tier fallback chain: RDAP, WHOIS, and NS-based inference.
- **Data Model**: Stores complete analysis results in a `full_results` JSON column for historical playback and integrity. Includes schema versioning for future compatibility.
- **Security Hardening**: Implements SSRF protection, CSRF protection, thread-safe caching, and strict IDNA encoding.
- **Performance**: Utilizes a shared ThreadPoolExecutor, DNS result TTL cache, and CT cache. Includes semaphore-based concurrency control.
- **Network Telemetry**: `network_telemetry.py` — per-provider health tracking (success rate, latency, consecutive failures), adaptive exponential backoff (500ms–30s), operation-specific timeouts. Exposes `/api/health` dashboard. Thread-safe singleton with non-reentrant locks (avoid calling properties from within locked blocks).
- **Remediation Guidance**: `remediation_guidance.py` — maps analysis verdicts to prioritized, RFC-cited fix recommendations. Generates "Top 3 Fixes" sorted by severity (Critical > High > Medium > Low) and per-section guidance for SPF, DKIM, DMARC, DNSSEC, DANE, MTA-STS, TLS-RPT, BIMI, CAA. Context-aware: skips DKIM/MTA-STS/BIMI for no-mail domains, blocks BIMI when DMARC not enforced, suggests DANE only when DNSSEC is active.
- **Testing**: Employs formal JSON Schema for contract testing, a golden fixture system for regression testing, and dependency injection for deterministic testing. DNSAnalyzer supports `offline_mode` to disable all outbound network calls (DoH, RDAP, WHOIS, CT logs, SMTP, DNSSEC AD validation, NS delegation) for fast deterministic tests. CI script at `scripts/run_contract_tests.sh` (default: fast offline tests; `./scripts/run_contract_tests.sh full` for integration tests). Test suite: 139 tests.
- **History Export**: Streaming NDJSON export of all analysis history via `/export/json`.
- **Comparison View**: Side-by-side diff of two analyses of the same domain at `/compare`.

### Database Migrations
- **Flask-Migrate (Alembic)**: Schema evolution tool. Run `flask db migrate -m "description"` to generate migrations, `flask db upgrade` to apply. Current schema stamped at head — future changes auto-detected.

### Frontend
- **Technology**: Server-rendered HTML with Jinja2 templates, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **Features**: PWA support (manifest, service worker), comprehensive accessibility features (ARIA landmarks, skip-to-content), and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare (diff view for two scans of same domain).

### Design Patterns
- MVC-style separation.
- Singleton pattern for `DNSAnalyzer`.
- JSON columns for flexible data storage.

### Quality of Life & Performance
- Critical inline CSS, preconnect hints, per-IP rate limiting, re-analyze countdown, SEO optimization, and native system fonts.

## External Dependencies

### Python Packages
- **Flask**: Web framework.
- **Flask-SQLAlchemy**: ORM integration.
- **Flask-Migrate**: Alembic-based database migration management.
- **dnspython**: DNS query library.
- **requests**: HTTP client.
- **idna**: Internationalized domain name encoding.

### External Services
- **Cloudflare DNS**: Consensus resolver.
- **Google Public DNS**: Consensus resolver.
- **Quad9**: Consensus resolver.
- **OpenDNS/Cisco Umbrella**: Consensus resolver.
- **IANA RDAP**: Registry data lookups.
- **ip-api.com**: IP-to-country lookup.
- **crt.sh**: Certificate Transparency logs.

### Database
- **PostgreSQL**: Managed by Replit.