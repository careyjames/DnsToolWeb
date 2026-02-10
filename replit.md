# DNS Tool — Domain Security Audit

## Overview

The DNS Tool is a web-based intelligence platform for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), with automatic subdomain discovery via Certificate Transparency logs and DNS probing. The tool aims to be an educational authority, providing accurate, RFC-cited, and verifiable results, focusing on elevating domain security through actionable insights.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application is currently undergoing a rewrite from Python/Flask to Go/Gin for improved performance and concurrency. The architecture follows an MVC-style separation.

### Backend (Python - current production)
- **Frameworks**: Flask, SQLAlchemy (ORM), PostgreSQL.
- **DNS Analysis Engine**: Utilizes `dnspython` for extensive record queries, email security analysis, and DNS evidence diffing, employing multiple external resolvers for consensus.
- **Subdomain Discovery**: Combines Certificate Transparency logs, DNS probing, and CNAME chain traversal, prioritizing security-relevant subdomains.
- **Registrar Lookup**: Employs a three-tier fallback (RDAP, WHOIS, NS-based inference).
- **Data Model**: Stores complete analysis results in a `full_results` JSON column with schema versioning.
- **Security**: Implements SSRF protection, CSRF protection, thread-safe caching, and strict IDNA encoding.
- **Performance**: Uses ThreadPoolExecutor, DNS result TTL cache, CT cache, and semaphore-based concurrency control.
- **Network Telemetry**: Tracks per-provider health, implements adaptive exponential backoff, and provides an `/api/health` dashboard.
- **Remediation Guidance**: Maps analysis verdicts to prioritized, RFC-cited fix recommendations (e.g., "Top 3 Fixes") and context-aware per-section guidance.
- **Testing**: Employs JSON Schema for contract testing, a golden fixture system for regression testing, and dependency injection, with an `offline_mode` for deterministic tests.
- **Features**: Includes streaming NDJSON export of analysis history and a side-by-side comparison view of two analyses.

### Backend (Go - in progress)
- **Web Framework**: Gin.
- **Database**: `pgx` v5 for PostgreSQL with `sqlc` for type-safe query generation.
- **DNS**: `miekg/dns` (planned).
- **Templates**: Go `html/template`.
- **Project Structure**: Organized with `cmd`, `internal` (config, db, dbq, handlers, middleware, models, templates), `db/queries`, `templates` directories.
- **Current Status**: All HTTP routes ported, SQLC integration for type-safe database queries, template migration is complete. DNS engine, security features, telemetry, and test parity are remaining phases.

### Frontend
- **Technology**: Server-rendered HTML with Jinja2 templates (Python) / Go `html/template` (Go), Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **Features**: PWA support, comprehensive accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare.

## External Dependencies

### Python Packages
- **Flask**: Web framework.
- **Flask-SQLAlchemy**: ORM integration.
- **Flask-Migrate**: Database migration management.
- **dnspython**: DNS query library.
- **requests**: HTTP client.
- **idna**: Internationalized domain name encoding.

### External Services
- **Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella**: Consensus DNS resolvers.
- **IANA RDAP**: Registry data lookups.
- **ip-api.com**: IP-to-country lookup.
- **crt.sh**: Certificate Transparency logs.

### Database
- **PostgreSQL**: Primary database.

## Go Rewrite — Migration Status

### All Phases COMPLETE — Go Server Ready for Production

**Completed Phases**:
- **Phase 1**: Foundation — Go project skeleton with Gin, pgx, slog, security middleware, health endpoint
- **Phase 2**: Database — sqlc integration for type-safe queries, 6 integration tests passing
- **Phase 3**: HTTP Routes — All routes ported
- **Phase 4**: Template Migration — All 6 Jinja2 templates converted to Go html/template (3,851 lines total), 4 shared partials, 50+ FuncMap helpers
- **Phase 5**: DNS engine — all 11 analyzers ported to Go (~4,960 lines), multi-resolver consensus DNS client, DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator
- **Phase 6**: Security — CSRF middleware (HMAC-signed cookie tokens), rate limiting (8/min/IP sliding window + anti-repeat), SSRF hardened (CGNAT, benchmark, documentation ranges), API route exemptions
- **Phase 7**: Telemetry & RDAP cache — provider health registry (success/failure counts, latency p50/p95, cooldown), RDAP response cache (TTL 24h per RFC 9224, 500 entries), enhanced /api/health endpoint
- **Phase 8**: Test parity — 92 Go tests across 6 packages (analyzer, db, dnsclient, handlers, middleware, telemetry)
- **Phase 9**: Native analysis wiring — /analyze handler uses Go DNS engine directly (no Python proxy), geo IP lookup, DB persistence, results rendering. E2E browser tested with google.com, apple.com, usa.gov, cloudflare.com.

**RDAP Cache TTL**: 24 hours, per RFC 9224 Section 8 recommendation and standard industry practice (Go openrdap reference implementation default). IANA bootstrap registry data changes infrequently; 24h is the minimum recommended cache duration.

**Python Dependency**: Fully eliminated. The Go server no longer proxies any requests to Python. All routes — analysis, subdomains API, history, stats, compare, export — are handled natively in Go. Python codebase remains in repo for reference but is not required to run the Go server.

**Cutover Complete**: Go server now serves production traffic on port 5000. The workflow's gunicorn command is intercepted by `.pythonlibs/bin/gunicorn` (a bash wrapper that `exec`s the Go binary). A backup of the original gunicorn exists at `.pythonlibs/bin/gunicorn.real`. The wrapper auto-builds the Go binary if needed and falls back to Python gunicorn if the Go build fails. `main.py` is kept as a no-op import for compatibility.

## Recent Changes

- **2026-02-10**: Production cutover complete. Go server now handles all traffic on port 5000 via gunicorn wrapper. Workflow remains stable (RUNNING state). Full analysis verified with all 9 DNS categories (SPF, DKIM, DMARC, DANE, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA).
- **2026-02-10**: Version bumped to 26.12.0. Security dependency update: downgraded quic-go (v0.54.0 removed), gin adjusted to v1.10.1. All 92 Go tests pass. Ready for cutover evaluation.
- **2026-02-10**: Python proxy fully removed. APISubdomains now uses native Go DiscoverSubdomains. proxyToPython function and PythonBackendURL config deleted. BasicRecords/AuthoritativeRecords now properly stored in DB. RDAP cache TTL text corrected from "6 hours" to "24 hours" (RFC 9224). Version bumped to 26.11.0.
- **2026-02-10**: Phase 9 complete — Native Go analysis wiring. /analyze handler uses Go DNS engine directly (no Python proxy for domain analysis). Added saveAnalysis helper, lookupCountry geo IP function, result extraction helpers. ViewAnalysis delegates to ViewAnalysisStatic. E2E browser tested: google.com (STRONG), apple.com (STRONG Monitoring), usa.gov, cloudflare.com all analyzed correctly with posture grades, remediation guidance, and full section data.
- **2026-02-10**: Phase 8 complete — 92 Go tests across 6 packages. Analyzer tests: schema contracts, posture scoring (grade boundaries, issue tracking, score capping), non-existent domain handling, government/enterprise/managed provider detection, behavioral verdict logic (email spoofing), utility functions. Middleware tests: CSRF (token generation, signing, validation, API exemptions), rate limiter (sliding window, anti-repeat, case insensitivity), security headers (CSP with nonce, HSTS, X-Frame-Options). dnsclient tests: SSRF IP filtering (private, loopback, CGNAT, documentation, benchmark ranges). Telemetry tests: provider health registry (success/failure, cooldown, backoff, health states), TTLCache (set/get, expiration, eviction, concurrent access). Handler tests: health endpoint, sitemap, static files.
- **2026-02-10**: Phase 7 complete — telemetry package with provider health registry (per-provider success/failure counts, rolling latency p95, adaptive cooldown with exponential backoff). Generic TTLCache for RDAP results (24h TTL, 500 max entries, hit/miss tracking). Telemetry wired into RDAP and CT log providers. Enhanced /api/health endpoint with provider health summary, cache stats, and overall health state. Analyzer instance created in main.go.
- **2026-02-10**: Phase 6 complete — CSRF middleware with HMAC-signed cookie tokens (SESSION_SECRET), rate limiting middleware (8 req/min/IP sliding window + 15s anti-repeat per domain), SSRF hardened with CGNAT/benchmark/documentation IP ranges, proxy handler uses consolidated IsPrivateIP, API routes exempted from CSRF, CSRF token injected into all 23 template render calls.
- **2026-02-10**: Phase 5 complete — all 11 DNS analyzers ported to Go (~4,960 lines). SPF, DMARC, DKIM, MTA-STS, TLS-RPT, CAA, DANE/TLSA, BIMI, DNSSEC, NS delegation, registrar lookup. Multi-resolver consensus DNS client with DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator.
- **2026-02-10**: Phase 4 complete — all 6 Jinja2 templates converted to Go html/template. Created shared partials (_head, _nav, _footer, _flash), 50+ FuncMap helpers for map access (mapGetStr/Map/Slice/Float/Bool), formatting, and conditionals. All handlers updated from c.JSON to c.HTML. Fixed SecurityHeaders middleware to set headers before c.Next(). Fixed unclosed {{if}} block in results.html template.
- **2026-02-10**: Go rewrite Phase 3 complete — all HTTP routes ported from Python/Flask to Go/Gin.
- **2026-02-10**: Go rewrite Phase 2 complete — sqlc integration for type-safe database queries.
- **2026-02-10**: Started Go rewrite — Phase 1 foundation complete.
- **2026-02-09**: Security hardening, asset cleanup, .gitignore additions.