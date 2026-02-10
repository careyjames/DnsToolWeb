# DNS Tool — Domain Security Audit

## Overview

The DNS Tool is a web-based intelligence platform for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), with automatic subdomain discovery via Certificate Transparency logs and DNS probing. The tool aims to be an educational authority, providing accurate, RFC-cited, and verifiable results, focusing on elevating domain security through actionable insights.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application has been fully rewritten from Python/Flask to Go/Gin for improved performance and concurrency. Python codebase remains in repo for reference only. The architecture follows an MVC-style separation.

### Backend (Go - production)
- **Web Framework**: Gin.
- **Database**: `pgx` v5 for PostgreSQL with `sqlc` for type-safe query generation.
- **DNS**: `miekg/dns` for all DNS queries.
- **Templates**: Go `html/template`.
- **Module**: `go.mod` at project root (module name: `dnstool`). Go source lives in `go-server/` with imports as `dnstool/go-server/internal/...`.
- **Project Structure**: `go-server/cmd/server/` (entry point), `go-server/internal/` (config, db, dbq, handlers, middleware, models, templates, analyzer, dnsclient, telemetry, providers), `go-server/db/queries/`, `go-server/templates/`.
- **Build**: `go build -o dns-tool-server ./go-server/cmd/server/` from project root.
- **Deployment**: Autoscale deployment. Build command: `CGO_ENABLED=0 go build -o dns-tool-server ./go-server/cmd/server/`. Run command: `./dns-tool-server`. Binary listens on 0.0.0.0:5000. Note: `CGO_ENABLED=0` is required because the deployment runtime lacks gcc; all dependencies (pgx, gin, miekg/dns) are pure Go and work without CGO.
- **Development**: Workflow uses gunicorn wrapper (`.pythonlibs/bin/gunicorn`) that exec's the pre-built Go binary.

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

**Cutover Complete**: Go server serves all traffic on port 5000. Development workflow uses gunicorn wrapper (`.pythonlibs/bin/gunicorn`) that exec's the Go binary. Deployment uses direct `go build` + `./dns-tool-server`. `main.py` kept as no-op for workflow compatibility.

## Recent Changes

- **2026-02-10**: Posture scoring rebalanced. Core email security (SPF/DMARC/DKIM) now weighted higher (60/100 max). Advanced optional features (DNSSEC/DANE/BIMI) reduced to bonus weight (15/100). Provider-aware DKIM: known providers (Google Workspace, Microsoft 365, etc.) get near-full credit even when selectors aren't discoverable. Thresholds: STRONG≥85/70, GOOD≥55, FAIR≥40, WEAK≥25, CRITICAL<25. Google.com now scores STRONG (85/100), Apple.com STRONG (79/100). Added 2 new provider-aware DKIM tests (94 total). TCP fallback for authoritative DNS queries (Replit blocks UDP port 53). Evidence diff now shows matching records on both sides.
- **2026-02-10**: Bug fixes — Posture bar, Evidence Diff, RDAP coverage. (1) Fixed DNS & Trust Posture bar: CalculatePosture now returns all template-required fields (state, icon, message, monitoring, configured, absent, deliberate_monitoring). States are STRONG/GOOD/FAIR/WEAK/CRITICAL. (2) Fixed DNS Evidence Diff showing 0/0 records: mapGetSlice template helper now handles []string and []map[string]interface{} via type switch (was only []interface{}). (3) Expanded RDAP/WHOIS TLD coverage: added 15 new TLDs (tech, site, store, info, biz, mobi, name, pro, cloud, online, live, space, fun, top). (4) Updated posture tests to new state-based naming. All 92 tests pass.
- **2026-02-10**: Module restructure for clean deployment. Moved `go.mod`/`go.sum` to project root. Updated all 43 import paths from `dnstool/internal/` to `dnstool/go-server/internal/`. Deployment now uses simple `go build -o dns-tool-server ./go-server/cmd/server/` + `./dns-tool-server`. All 92 tests pass.
- **2026-02-10**: SonarQube code quality refactoring. Reduced cognitive complexity across 14 Go files: templates/funcs.go (119 to <15), handlers/health.go (23 to <15), analyzer/dkim.go (107 to <15), 8 analyzer files refactored. Extracted 55+ constants for DKIM selectors/providers, 19 constants for provider categories. Created shared classifyHTTPError utility.
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