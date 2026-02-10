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

### Current Phase: Phase 4 — Template Migration (COMPLETE)

**Completed Phases**:
- **Phase 1**: Foundation — Go project skeleton with Gin, pgx, slog, security middleware, health endpoint
- **Phase 2**: Database — sqlc integration for type-safe queries, 6 integration tests passing
- **Phase 3**: HTTP Routes — All routes ported, reverse proxy for DNS-engine-dependent routes
- **Phase 4**: Template Migration — All 6 Jinja2 templates converted to Go html/template (3,851 lines total), 4 shared partials, 50+ FuncMap helpers, all handlers render HTML

**Completed Phases (continued)**:
- **Phase 5**: DNS engine — all 11 analyzers ported to Go (~4,960 lines), multi-resolver consensus DNS client, DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator
- **Phase 6**: Security — CSRF middleware (HMAC-signed cookie tokens), rate limiting middleware (8/min/IP sliding window + anti-repeat), SSRF hardened (CGNAT, benchmarking, documentation ranges), API route exemptions

**Remaining Phases**:
- **Phase 7**: Telemetry & RDAP cache — health tracking, backoff, caching
- **Phase 8**: Test parity — port test suite; Python tests as acceptance tests during transition

**Parallel Operation**: Python app serves production traffic on port 5000. Go server runs on port 5001 for testing.

## Recent Changes

- **2026-02-10**: Phase 6 complete — CSRF middleware with HMAC-signed cookie tokens (SESSION_SECRET), rate limiting middleware (8 req/min/IP sliding window + 15s anti-repeat per domain), SSRF hardened with CGNAT/benchmark/documentation IP ranges, proxy handler uses consolidated IsPrivateIP, API routes exempted from CSRF, CSRF token injected into all 23 template render calls.
- **2026-02-10**: Phase 5 complete — all 11 DNS analyzers ported to Go (~4,960 lines). SPF, DMARC, DKIM, MTA-STS, TLS-RPT, CAA, DANE/TLSA, BIMI, DNSSEC, NS delegation, registrar lookup. Multi-resolver consensus DNS client with DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator.
- **2026-02-10**: Phase 4 complete — all 6 Jinja2 templates converted to Go html/template. Created shared partials (_head, _nav, _footer, _flash), 50+ FuncMap helpers for map access (mapGetStr/Map/Slice/Float/Bool), formatting, and conditionals. All handlers updated from c.JSON to c.HTML. Fixed SecurityHeaders middleware to set headers before c.Next(). Fixed unclosed {{if}} block in results.html template.
- **2026-02-10**: Go rewrite Phase 3 complete — all HTTP routes ported from Python/Flask to Go/Gin.
- **2026-02-10**: Go rewrite Phase 2 complete — sqlc integration for type-safe database queries.
- **2026-02-10**: Started Go rewrite — Phase 1 foundation complete.
- **2026-02-09**: Security hardening, asset cleanup, .gitignore additions.