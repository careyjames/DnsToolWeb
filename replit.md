# DNS Analysis Tool

## Overview

A web-based DNS intelligence tool for comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), and DNS security intelligence reports. The application aims to provide a robust, user-friendly platform for understanding and improving domain and email security posture, offering insights into business vision, market potential, and project ambitions.

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