# DNS Analysis Tool

## Overview

This project is a web-based DNS intelligence tool designed for comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), email security management provider detection, and generation of DNS security intelligence reports. Its primary purpose is to offer a robust, user-friendly platform that helps users understand and enhance their domain and email security posture. The tool provides insights into crucial aspects of domain configuration, aiming to improve overall digital security.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes (v26.10.52)
- Performance optimization: Parallel resolver consensus (v26.10.52):
  - Resolver consensus checks for 4 critical record types (A, MX, NS, TXT) now run in parallel via `ThreadPoolExecutor(max_workers=4)` instead of sequentially.
  - `resolver_consensus` task reduced from ~17s to ~4.4s (74% faster).
  - Overall analysis time improvements: example.com 17.5s→6.6s (-62%), cloudflare.com 17.1s→11.3s (-34%).
  - Enhanced timing instrumentation: parallel lookup log line now shows the 5 slowest tasks with per-task durations.
- DNS-augmented Subdomain Discovery (v26.10.51):
  - Wildcard TLS certificate detection: identifies `*.domain` certificates in CT logs and flags them in the UI.
  - When a wildcard cert is found, DNS probing of ~80 common subdomain names runs in parallel (20 workers) to discover subdomains covered by the wildcard.
  - Wildcard DNS filtering: probes a random non-existent subdomain to detect wildcard DNS records, filtering out false positives.
  - Subdomain table gains a "Source" column showing "CT Log" or "DNS" for each entry.
  - Wildcard cert info alert explains why subdomains may not appear individually in CT logs (RFC 6962).
  - Fixes unreadable badge contrast on dark theme: "3/3 controls" and "X/3 controls" badges now use solid backgrounds with proper text contrast.
- Graduated Mail Posture classification (v26.10.50):
  - New `_classify_mail_posture()` method provides RFC-grounded assessment of email intent.
  - Four graduated classifications: No-Mail: Verified, No-Mail: Partial, Email: Ambiguous, Email: Enabled.
  - Each signal (Null MX / RFC 7505, SPF -all / RFC 7208, DMARC reject / RFC 7489) evaluated individually.
  - Missing-step checklist with RFC citations and risk explanations for partial configurations.
  - Recommended DNS records displayed for incomplete no-mail domains.
  - Replaces binary is_no_mail_domain banner with context-aware graduated alerts.
  - RFC 5321 §5.1 A/AAAA fallback risk properly communicated for domains without Null MX.
- Intelligent subdomain detection (v26.10.49):
  - When analyzing a subdomain (e.g., `dnstool.it-help.tech`), the tool now detects this via the Public Suffix List (`tldextract`) and provides context-aware messaging instead of "no subdomains found".
  - Explains that CT enumeration scope is bounded by the queried label (RFC 1034 §3.1, RFC 8499).
  - Offers a one-click link to scan the registered/base domain for broader subdomain discovery.
  - `_get_registered_domain()` method added to dns_analyzer.py using eTLD+1 computation.
- Subdomain Discovery now automatic (v26.10.48):
  - CT log query runs in parallel with all DNS lookups — no button click needed.
  - Results stored in `ct_subdomains` JSON column, persisted across report views.
  - Server-rendered via Jinja2 template instead of client-side JavaScript fetch.
  - Older reports without CT data show "not available" message.
  - Thread pool increased to 15 workers; futures timeout to 25s.
- DNS Evidence Diff improvements (v26.10.47):
  - CAA and SOA record types added; TTL badges; RFC reference links.
  - Auth timeout shows "Timeout" status instead of misleading red styling.

## System Architecture

### Backend Framework
- **Flask** is used as the web framework.
- **SQLAlchemy** provides ORM functionality.
- **PostgreSQL** is the chosen database.

### Core Components

**Application Entry Points:**
- `main.py`: The application's simple entry point.
- `app.py`: Contains Flask configuration, database models, and route handlers.

**DNS Analysis Engine:**
- `dns_analyzer.py`: Encapsulates the core DNS analysis logic utilizing `dnspython`.
- **Features**: Domain validation, IDNA encoding, DNS record queries, and email security analysis (SPF, DMARC, DKIM, MTA-STS, TLS-RPT).
- Employs multiple external DNS resolvers (Cloudflare, Google, Quad9, OpenDNS/Cisco Umbrella) for consensus and discrepancy detection.
- Fetches IANA RDAP data for domain registry lookups.
- Performs SMTP Transport Verification (STARTTLS, TLS version, cipher strength, certificate validity).
- Conducts DNS Infrastructure Analysis to identify enterprise DNS providers.
- Implements comprehensive DKIM selector discovery and key strength analysis.
- Detects DMARC monitoring, TLS-RPT reporting, and SPF flattening services.
- Supports context-aware DKIM selector attribution and SPF evidence hierarchy.
- **DNS Evidence Diff**: Compares resolver and authoritative records for various types, including A, AAAA, MX, TXT, NS, CAA, and SOA records, along with email security-related records (`_dmarc`, `_mta-sts`, `_smtp._tls`). Displays TTL values and RFC reference badges.
- **Subdomain Discovery**: Automatic Certificate Transparency log query (crt.sh, RFC 6962) runs in parallel during analysis. Discovers subdomains with TLS certificates, providing details like expiry, issuer, and wildcard status. Results stored in database and rendered server-side.
- **Null MX and No-Mail Domain Detection**: Recognizes `MX 0 .` (RFC 7505) and identifies domains explicitly configured not to send or receive email, adjusting posture scoring and verdicts accordingly.
- **Subdomain-aware analysis**: Correctly handles DNSSEC inheritance, NS delegation, and RDAP lookups for subdomains.
- **Subdomain-aware CT discovery**: Detects when the analyzed domain is itself a subdomain (via Public Suffix List / `tldextract`) and provides context-aware messaging with RFC references (RFC 8499, RFC 1034 §3.1), offering a one-click link to scan the registered domain for broader discovery.

**Data Model:**
- `DomainAnalysis` model: Stores analysis results including DNS records, authoritative records, SPF/DMARC status, policies, and visitor location in JSON fields.

### Frontend Architecture
- Server-rendered HTML templates powered by Jinja2.
- Utilizes a self-hosted Bootstrap dark theme with a native system font stack.
- Incorporates self-hosted and subsetted Font Awesome icons.
- Custom CSS (`static/css/custom.min.css`) and client-side JavaScript (`static/js/main.js`) are used for styling and interactivity.
- **PWA Support**: Includes a web app manifest, service worker, and app icons for "Install App" functionality and standalone operation.

**Pages:**
- Index (home): Domain input form.
- Results: Detailed DNS analysis display.
- History: List of past analyses.
- Statistics: Usage trends and metrics.

**Route Structure:**
- `GET /`: Homepage.
- `GET|POST /analyze`: Domain analysis processing.
- `GET /analysis/{id}`: View saved analysis.
- `GET /history`: List of past analyses.
- `GET /stats`: Usage metrics dashboard.
- `GET /statistics`: Redirects to `/stats`.
- `GET /robots.txt`: Search engine crawler guidance.
- `GET /sitemap.xml`: Dynamic sitemap.
- `GET /llms.txt`: AI agent quick-start guide.
- `GET /llms-full.txt`: AI agent comprehensive driving guide.

### Design Patterns
- Adheres to an MVC-style separation.
- Employs a Singleton pattern for `DNSAnalyzer`.
- Utilizes JSON columns in PostgreSQL for flexible data storage.

### Quality of Life & Performance
- Implements critical inline CSS and preconnect hints.
- Features per-IP rate limiting (8 analyses per minute) backed by Redis.
- Offers a re-analyze countdown UI.
- Ensures data freshness: DNS records are fetched live; RDAP data is cached with a 6-hour TTL.
- SEO optimized with rich schema and meta tags.
- Uses a native system font stack.
- Provider attribution badges use a warm gold/amber color for readability.
- Code blocks are optimized for monospace readability.
- Includes print styles for readability on paper.

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