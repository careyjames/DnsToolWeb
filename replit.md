# DNS Analysis Tool

## Overview

A web-based DNS intelligence tool for comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), email security management provider detection, and DNS security intelligence reports. The application aims to provide a robust, user-friendly platform for understanding and improving domain and email security posture, offering insights into business vision, market potential, and project ambitions.

## Recent Changes (v26.10.27)
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
- `POST /analyze`: Processes domain analysis.
- `GET /analysis/{id}`: View saved analysis.
- `GET /history`: List of past analyses.
- `GET /statistics`: Usage metrics dashboard.

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