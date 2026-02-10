# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records such as SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, and CAA, with automatic subdomain discovery. The tool aims to provide accurate, RFC-cited, and verifiable results, focusing on elevating domain security through actionable insights and serving as an educational authority.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application is implemented in Go using the Gin framework, having been rewritten from a Python/Flask codebase for improved performance and concurrency. The architecture follows an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin web framework, `pgx` v5 for PostgreSQL, `sqlc` for type-safe query generation, and `miekg/dns` for all DNS queries.
- **Templates**: Go `html/template`.
- **Project Structure**: `go-server/cmd/server/` (entry point), `go-server/internal/` (config, db, handlers, middleware, models, templates, analyzer, dnsclient, telemetry, providers), `go-server/db/queries/`, `go-server/templates/`.
- **Key Features**: Multi-resolver consensus DNS client with DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator, CSRF middleware (HMAC-signed cookie tokens), rate limiting, SSRF hardening, and telemetry for provider health monitoring and RDAP caching.
- **Posture Evaluation**: Risk levels are CVSS-aligned (Critical, High, Medium, Low, Informational), derived from actual protocol states and providing comprehensive remediation guidance with RFC citations.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, comprehensive accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella (for consensus).
- **IANA RDAP**: For registry data lookups.
- **ip-api.com**: For IP-to-country lookups.
- **crt.sh**: For Certificate Transparency logs.

### Database
- **PostgreSQL**: The primary database for persistent storage.