# DNS Analysis Tool

## Overview

A web-based DNS intelligence tool for comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), email security management provider detection, and DNS security intelligence reports. The application aims to provide a robust, user-friendly platform for understanding and improving domain and email security posture, offering insights into business vision, market potential, and project ambitions.

## Recent Changes (v26.10.39)
- Renamed "NS delegation" to "Dynamic Services" for email security subzone delegation detection. "NS delegation" now reserved for actual authoritative nameserver delegation (e.g., domain at GoDaddy with NS at Cloudflare). Dynamic Services detection shows capability labels (Dynamic DMARC, Dynamic DKIM, Dynamic MTA-STS, Dynamic TLS-RPT) instead of raw zone names (v26.10.39).
- Dynamic Services provider detection: detects providers (Red Sift/OnDMARC, Mailhardener) via DNS subzone delegation on _dmarc, _domainkey, _mta-sts, _smtp._tls zones. Merges with existing provider detection (DMARC rua, TLS-RPT, MTA-STS CNAME). Fixed variable shadowing bug where loop variable `domain` overwrote method parameter (v26.10.38).

### Older Changes (v26.10.29)
- Self-hosted Bootstrap JS bundle — eliminates last external CDN dependency (cdn.jsdelivr.net), removes intermittent Cloudflare `__cf_bm` third-party cookie that caused Best Practices score to drop to 81 (v26.10.29).
- CSP tightened: script-src no longer allowlists cdn.jsdelivr.net (v26.10.29).
- PWA support: web app manifest, service worker, and app icons enable Chrome "Install App" and Mac dock pinning — opens as standalone app without browser chrome (v26.10.28).
- AI agent documentation: `llms.txt` and `llms-full.txt` rewritten as step-by-step guides teaching AI agents (ChatGPT, Gemini, Claude, Perplexity) how to operate the tool — direct URL method, form interaction, result interpretation, and re-analyze flow (v26.10.28).
- Dynamic sitemap: `/sitemap.xml` now generated dynamically with automatic `lastmod` dates (always today's date), includes `/statistics` route (v26.10.28).
- `robots.txt` updated with AI agent documentation pointers (`/llms.txt`, `/llms-full.txt`) (v26.10.28).
- Self-hosted Bootstrap dark theme CSS — eliminates external cdn.replit.com dependency and removes wasted 750ms Google Fonts (IBM Plex Sans) render-blocking load (v26.10.27).
- CSP tightened: style-src and font-src now 'self' only (no external CDN allowlisting needed) (v26.10.27).
- Static file cache headers: 1-year max-age for all static assets (v26.10.27).
- Removed all Google Fonts preconnect hints and cdn.replit.com preconnect/dns-prefetch from all templates (v26.10.27).
- CSS properly minified with real minification (comments, whitespace, redundant semicolons removed) (v26.10.27).
- Provider attribution badges use warm gold/amber `.provider-badge` class for trust-signal readability (v26.10.24).
- Code blocks optimized with explicit text color, line-height 1.65, letter-spacing 0.015em for monospace readability (v26.10.24).
- DNS Hosting column badges (Gov/Enterprise) no longer truncated — removed text-truncate (v26.10.25).
- Homepage meta descriptions, OG/Twitter tags, keywords, JSON-LD schema, feature cards, persona cards, and FAQ answers updated to reflect email security management provider detection, TLS-RPT, and SMTP transport encryption capabilities (v26.10.26).

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Framework
- **Flask** as the web framework.
- **SQLAlchemy** for ORM functionality.
- **PostgreSQL** for database storage.

### Core Components

**Application Entry Points:**
- `main.py`: Simple entry point.
- `app.py`: Main application file, including Flask configuration, database models, and route handlers.

**DNS Analysis Engine:**
- `dns_analyzer.py`: Core DNS analysis logic using `dnspython`.
- Features: Domain validation, IDNA encoding, DNS record queries, email security analysis (SPF, DMARC, DKIM).
- Utilizes multiple external DNS resolvers (Cloudflare, Google, Quad9, OpenDNS/Cisco Umbrella) for consensus and discrepancy detection.
- Fetches IANA RDAP data for domain registry lookups.
- Performs SMTP Transport Verification (STARTTLS, TLS version, cipher strength, certificate validity).
- Conducts DNS Infrastructure Analysis to detect enterprise DNS providers and suggest security measures.
- Implements comprehensive DKIM selector discovery and key strength analysis.
- Detects and displays DMARC monitoring, TLS-RPT reporting, and SPF flattening services.
- Context-aware DKIM selector attribution and SPF evidence hierarchy.

**Data Model:**
- `DomainAnalysis` model: Stores analysis results with JSON fields for DNS records, authoritative records, SPF/DMARC status, policies, and visitor location (`country_code`, `country_name`).

### Frontend Architecture
- Server-rendered HTML templates using Jinja2.
- Bootstrap dark theme with a native system font stack.
- Self-hosted and subsetted Font Awesome icons.
- Custom CSS (`static/css/custom.min.css`) and client-side JavaScript (`static/js/main.js`).

**Pages:**
- Index (home): Domain input form.
- Results: Detailed DNS analysis display.
- History: List of past analyses.
- Statistics: Usage trends and metrics, including visitor countries.

**Route Structure:**
- `GET /`: Homepage.
- `GET|POST /analyze`: Processes domain analysis (GET via `?domain=` query param, POST via form).
- `GET /analysis/{id}`: View saved analysis.
- `GET /history`: List of past analyses.
- `GET /stats`: Usage metrics dashboard.
- `GET /statistics`: Redirects to `/stats`.
- `GET /robots.txt`: Search engine crawler guidance (static file).
- `GET /sitemap.xml`: Dynamic sitemap with automatic `lastmod` dates.
- `GET /llms.txt`: AI agent quick-start guide (static file).
- `GET /llms-full.txt`: AI agent comprehensive driving guide (static file).

### Design Patterns
- MVC-style separation (Flask routes, SQLAlchemy models, Jinja2 templates).
- Singleton pattern for `DNSAnalyzer`.
- JSON columns in PostgreSQL for flexible data.

### Quality of Life & Performance
- Critical inline CSS and preconnect hints for performance.
- Per-IP rate limiting (8 analyses per minute) with Redis-backed solution.
- Re-analyze countdown UI.
- Data freshness: DNS records always fetched fresh; RDAP data cached (6-hour TTL).
- SEO optimization with rich schema and meta tags.
- Native system font stack for improved performance and aesthetics.
- Provider attribution badges use warm gold/amber `.provider-badge` class for trust-signal readability (v26.10.24).
- Code blocks optimized with explicit text color, line-height 1.65, letter-spacing for monospace readability.
- Print styles for `.provider-badge` (cream/brown) and code blocks ensure paper readability.
- IMPORTANT: `custom.min.css` must be kept in sync with `custom.css` (templates reference the `.min` version).
- IMPORTANT: When adding new public routes, add them to the dynamic sitemap in `app.py` (`sitemap()` function) and update `llms.txt`/`llms-full.txt` if user-facing.
- Sitemap `lastmod` is automatic (always today's date) — no manual updates needed.
- `llms.txt` (static/llms.txt): Quick-start guide for AI agents. Update when capabilities change.
- `llms-full.txt` (static/llms-full.txt): Comprehensive agent driving guide. Update when result page structure, routes, or analysis features change.

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

### Database
- PostgreSQL (Replit-managed).