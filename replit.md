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
- **Testing**: Employs formal JSON Schema for contract testing, a golden fixture system for regression testing, and dependency injection for deterministic testing. DNSAnalyzer supports `offline_mode` to disable all outbound network calls (DoH, RDAP, WHOIS, CT logs, SMTP, DNSSEC AD validation, NS delegation) for fast deterministic tests. CI script at `scripts/run_contract_tests.sh` (default: fast offline tests; `./scripts/run_contract_tests.sh full` for integration tests). Test suite: 229 tests.
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

## Security Audit Log

### Review Date: 2026-02-09

**SSRF Protection** — Verified complete coverage:
- `_safe_http_get()` in `dns_analyzer.py` wraps all user-influenced outbound requests with `_validate_url_target()` (DNS resolution + private IP rejection).
- BIMI logo proxy (`/proxy/bimi-logo`) in `app.py` uses `_validate_parsed_url()` + `_check_ssrf()` + `_build_safe_url()` with redirect validation, response size limits, and content-type enforcement.
- Direct `requests.get()` calls to hardcoded trusted endpoints (IANA RDAP bootstrap, Google DoH, crt.sh, ip-api.com) are not SSRF-vulnerable since URLs are fixed constants or query-parameterized against known hosts.

**XSS Protection** — No uses of Jinja2 `|safe` filter in templates. All user-controlled data is auto-escaped by Jinja2. CSP nonces are applied to inline scripts.

**Session Security** — Cookies set with `Secure`, `HttpOnly`, `SameSite=Lax`. Secret key sourced from environment variable.

**Input Validation** — Domain inputs are IDNA-encoded and validated. URL inputs are parsed, scheme-restricted, and SSRF-checked.

**Remaining Advisory Items** (low priority, no current exploit):
- `models.py` is empty; DB models live in `app.py`. Consider moving them to `models.py` for separation of concerns if the file grows further.
- `app.py` is large (~1,580 lines); routing, models, and utility functions coexist. Acceptable for now but worth modularizing if more features are added.
- Some direct `requests.get()` calls in `dns_analyzer.py` (DoH, CT logs) bypass `_safe_http_get()` — acceptable because they target hardcoded public API endpoints, not user-supplied URLs.

## Go Rewrite — Migration Status

### Current Phase: Phase 2 — Database Queries (COMPLETE)

**Decision**: Rewrite the DNS Tool from Python/Flask to Go for better performance and concurrency.

**Go Stack**:
- **Web Framework**: Gin (high-performance, middleware-friendly)
- **Database**: pgx v5 (native PostgreSQL driver with connection pooling) + sqlc (type-safe query generation)
- **DNS**: miekg/dns (planned for Phase 5)
- **Templates**: Go `html/template` with custom FuncMap for Jinja2 filter equivalents

**Project Structure** (`go-server/`):
```
go-server/
├── cmd/server/main.go          # Entry point
├── internal/
│   ├── config/config.go        # Environment-based configuration
│   ├── db/
│   │   ├── db.go               # PostgreSQL connection pool (pgx) + Queries accessor
│   │   └── db_test.go          # Integration tests (6 tests)
│   ├── dbq/                    # sqlc-generated type-safe query code
│   │   ├── db.go               # DBTX interface, Queries struct
│   │   ├── models.go           # DomainAnalysis, AnalysisStat structs
│   │   ├── domain_analyses.sql.go  # DomainAnalysis CRUD queries
│   │   └── analysis_stats.sql.go   # AnalysisStats queries
│   ├── handlers/               # HTTP route handlers
│   │   ├── health.go           # /go/health endpoint
│   │   └── home.go             # GET / homepage
│   ├── middleware/middleware.go # RequestContext, SecurityHeaders, Recovery
│   ├── models/models.go        # Legacy model structs (kept for reference)
│   └── templates/funcs.go      # Template helper functions (countryFlag, formatDate, etc.)
├── db/queries/                 # SQL query definitions for sqlc
│   ├── domain_analyses.sql     # All DomainAnalysis queries
│   └── analysis_stats.sql      # All AnalysisStats queries
├── sqlc.yaml                   # sqlc configuration
├── templates/index.html        # Phase 1 placeholder template
├── go.mod / go.sum
```

**What's Working**:
- Go binary compiles and runs
- Connects to existing PostgreSQL database (same DB as Python app)
- Health endpoint at `/go/health` returns DB status, memory stats, goroutine count
- Structured logging with slog (trace IDs, request timing)
- Security headers middleware (CSP with nonces, HSTS, X-Frame-Options, etc.)
- Template engine with custom helper functions (countryFlag, formatDate, formatDuration, dict, etc.)
- **sqlc-generated type-safe database queries** for all DomainAnalysis and AnalysisStats operations
- **DomainAnalysis queries**: CRUD, search by domain, list with pagination, count, popular domains, country distribution
- **AnalysisStats queries**: CRUD, list recent, upsert daily stats, date range queries
- **6 integration tests** passing against production PostgreSQL database

**Parallel Operation**: Python app continues serving production traffic on port 5000. Go server currently runs on port 5001 for testing only.

### Remaining Phases:
- **Phase 3**: HTTP routes — all Python routes ported (analyze, history, stats, compare, export, BIMI proxy)
- **Phase 4**: Template migration — convert 6 Jinja2 templates to Go html/template
- **Phase 5**: DNS engine — port 5,400-line analyzer to Go with miekg/dns + goroutine concurrency
- **Phase 6**: Security — SSRF protection, CSRF, rate limiting ported to Go
- **Phase 7**: Telemetry & RDAP cache — health tracking, backoff, caching
- **Phase 8**: Test parity — port test suite; Python tests as acceptance tests during transition

## Recent Changes

- **2026-02-10**: Go rewrite Phase 2 complete — sqlc integration for type-safe database queries. All DomainAnalysis and AnalysisStats operations ported with 6 integration tests passing. Database struct now exposes `Queries` accessor for handlers.
- **2026-02-10**: Started Go rewrite — Phase 1 foundation complete. Go project skeleton with Gin web framework, pgx database driver, structured logging, security headers middleware, health endpoint, and template engine. Python app continues serving production traffic.
- **2026-02-10**: Fixed 2 test failures (CSRF in test mode, trailing-dot domain validation). Test suite now at 229 passing tests.
- **2026-02-09**: Removed SonarQube report file (false positive gitleaks alert). Cleaned 271 accumulated attached asset files. Added `.gitignore` for `attached_assets/`, `__pycache__/`, `.cache/`, `node_modules/`.
- **2026-02-09**: Security hardening — host binding, token redaction in test fixtures, safe DOM manipulation, SSRF protection on BIMI proxy with redirect validation and response size limits.
- **2026-01-22**: Added collapsible DNS security fixes view, code block copy functionality, remediation guidance system, network telemetry with `/api/health` dashboard.
- **2026-01-22**: Fixed critical deadlock in network telemetry singleton. Improved error handling for SMTP verification timeouts and missing DNS record values.