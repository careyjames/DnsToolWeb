# DNS Analysis Tool

## Overview

A web-based DNS intelligence tool that provides comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), and DNS security intelligence reports. The application allows users to analyze domains, view DNS records, check email security configurations, and maintain a history of past analyses with usage statistics.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Backend Framework
- **Flask** serves as the web framework, handling HTTP requests and rendering templates
- **SQLAlchemy** provides ORM functionality with a declarative base pattern
- **PostgreSQL** is used as the database for storing domain analysis results (Replit-managed, reliable)

### Core Components

**Application Entry Points:**
- `main.py` - Simple entry point that imports the Flask app
- `app.py` - Main application file containing Flask configuration, database models, and route handlers

**DNS Analysis Engine:**
- `dns_analyzer.py` - Core DNS analysis logic using the `dnspython` library
- Handles domain validation, IDNA encoding for internationalized domains
- Queries DNS records and performs email security analysis (SPF, DMARC)
- Uses external DNS resolvers (default: 1.1.1.1) with configurable timeout
- Fetches IANA RDAP data for domain registry lookups
- SMTP Transport Verification: Checks MX server STARTTLS support, TLS version, cipher strength, and certificate validity
- DNS Infrastructure Analysis: Detects enterprise-grade DNS providers (Cloudflare, AWS, Google, Akamai, Azure) and explains alternative security measures when DNSSEC is not enabled

**Data Model:**
- `DomainAnalysis` model stores analysis results with JSON fields for flexible record storage
- Tracks basic DNS records, authoritative records, SPF/DMARC status and policies

### Frontend Architecture
- Server-rendered HTML templates using Jinja2
- Bootstrap dark theme for styling (loaded from CDN)
- Font Awesome icons for UI elements
- Custom CSS: `static/css/custom.css` (source) → `static/css/custom.min.css` (minified, used in production)
- Client-side JavaScript in `static/js/main.js` for form validation and UX enhancements
- CSS Minification: Run `python3 -c "import cssmin; ..."` to regenerate minified CSS after changes

**Pages:**
- Index (home) - Domain input form
- Results - Detailed DNS analysis display
- History - List of past analyses
- Statistics - Usage trends and metrics

**Route Structure:**
- `GET /` - Homepage with domain input form
- `POST /analyze` - Processes domain analysis and renders results directly (fresh analysis)
- `GET /analysis/{id}` - View saved analysis from history
- `GET /analysis/{id}/view` - Static view for rate-limited countdown scenarios
- `GET /history` - List of past analyses
- `GET /statistics` - Usage metrics dashboard

### Design Patterns
- MVC-style separation with Flask routes as controllers, SQLAlchemy models, and Jinja2 templates as views
- Singleton pattern for the DNSAnalyzer instance
- JSON columns in PostgreSQL for storing variable-structure DNS record data

## External Dependencies

### Python Packages
- **Flask** - Web framework
- **Flask-SQLAlchemy** - Database ORM integration
- **dnspython** - DNS query library for record lookups
- **requests** - HTTP client for external API calls (IANA RDAP)
- **idna** (optional) - Internationalized domain name encoding

### External Services
- **Cloudflare DNS (1.1.1.1)** - Default DNS resolver for queries
- **IANA RDAP** - Registry data for domain information lookups

### Frontend CDN Resources
- Bootstrap dark theme CSS
- Font Awesome icons

### Database
- PostgreSQL (Replit-managed via DATABASE_URL environment variable)

### Testing
- **pytest** - Unit test framework
- Test files: `tests/test_dns_analyzer.py` (50 unit tests), `tests/test_integration.py` (40 integration tests)
- Run tests: `python -m pytest tests/ -v`
- Total: 90 tests covering routes, rate limiting, scorecard logic, error states, schema bindings, consensus conflicts

## Recent Changes (v26.10.11)

### CSP Fix for Google Fonts & Perfect Best Practices Score (v26.10.11)
- Root cause: Replit Bootstrap dark theme CSS imports IBM Plex Sans via @import from fonts.googleapis.com
- CSP was blocking fonts.googleapis.com (style-src) and fonts.gstatic.com (font-src), causing console errors
- Added fonts.googleapis.com to style-src and fonts.gstatic.com to font-src in CSP
- Result: Best Practices score restored to 100% (was 74% in DebugBear / 92% in PageSpeed)
- Current Lighthouse scores (mobile): Performance 93-94, Accessibility 100, Best Practices 100, SEO 100
- Performance improvement from 88 → 93-94 attributed to cumulative optimizations: self-hosted Font Awesome subset (v26.10.5), CSS minification, reduced page weight (82KB from 260KB)

### CSS Minification Pipeline
- Source: `static/css/custom.css` (23KB) → Minified: `static/css/custom.min.css` (15KB), 35% reduction
- All templates reference `custom.min.css` for production serving
- Regenerate after CSS changes: `python3 -c "import cssmin; open('static/css/custom.min.css','w').write(cssmin.cssmin(open('static/css/custom.css').read()))"`

### DKIM Primary Platform Correlation (v26.10.8)
- DKIM selectors now attributed to known providers (MailChimp, Microsoft 365, Google, SendGrid, etc.)
- Cross-references found DKIM selectors with MX-detected primary mail platform
- New 'partial' DKIM status when DKIM found only for third-party services (not primary platform)
- Scorecard: third-party-only DKIM goes to "Monitoring" instead of "Configured"
- Verdict includes gap note: "DKIM found for X only — primary mail platform (Y) DKIM not verified"
- UI: provider badges on selectors, "Third-Party Only" badge, warning alert explaining gap
- MX provider detection expanded: o365, exchange, intermedia patterns for Microsoft-hosted Exchange
- Honest messaging: "primary provider may use custom selectors not discoverable through standard checks"
- Fixes false-positive "SECURE" verdicts when only marketing platform DKIM exists (e.g., MailChimp DKIM on Microsoft Exchange domain)

### Expanded RDAP/WHOIS TLD Coverage (v26.10.8)
- Added 55+ TLDs to both RDAP direct endpoints and WHOIS server mappings
- English-speaking: .uk, .nz, .ie, .gg, .je, .im, .ph, .in
- Popular: .co, .me, .ai, .cc, .tv, .ws, .to, .ly, .fm, .eu
- New gTLDs: .xyz, .online, .site, .store, .cloud, .info, .biz, .mobi, .name
- European ccTLDs: .lu, .dk, .fi, .no, .es, .pt, .cz, .sk, .hr, .ro, .hu, .bg, .lt, .lv, .ee, .gr, .si, .is, .rs, .li
- RDAP endpoints sourced from IANA bootstrap registry (data.iana.org/rdap/dns.json)
- All unmapped TLDs still fall back to rdap.org bootstrap service

### Asset Optimization & UX Fixes (v26.10.5)
- Self-hosted Font Awesome subset: 54 icons in 5.7KB woff2 (down from 150KB CDN), ~209KB total savings per page
- fontawesome-subset.min.css (16KB) replaces CDN CSS (81KB+572B)
- @font-face with font-display:swap for faster icon rendering (no invisible text flash)
- Removed unused "Font Awesome 6 Brands" font-family reference (no brand icons used)
- Removed cdnjs.cloudflare.com preconnect/dns-prefetch (no longer needed)
- CSP tightened: removed stale cdnjs.cloudflare.com and fonts.googleapis.com from style-src/font-src
- Loading overlay messages now use CSS @keyframes animation instead of JS setInterval (continues during page navigation)
- Removed redundant Enter key handler in main.js (fixes Safari form submission)
- Added /statistics → /stats redirect for URL consistency
- CSS Minification: custom.css (23KB) → custom.min.css (15KB)

### Visitor Country Tracking (v26.10.0)
- Added country_code and country_name columns to DomainAnalysis model
- IP-to-country lookup via free ip-api.com service (2s timeout, fails silently)
- Country tracked on both /analyze and /analysis/{id} routes
- "Visitor Countries" section on /stats page with flag emojis and count badges
- Jinja2 country_flag template filter converts ISO 3166-1 codes to flag emoji
- Country section only appears when geo data exists (progressive enhancement)
- Company description updated: emphasizes DNS expertise, email deliverability consulting, and remote support for organizations worldwide (no longer Apple-centric)

### SEO Multi-Persona Optimization (v26.9.1)
- Updated title, meta description, OG/Twitter tags with multi-persona keywords
- Added "Built for Every Level of Your Organization" section targeting executives, IT pros, DNS specialists, business/compliance
- Added 8-question FAQ accordion with FAQPage schema for rich search results
- Enhanced JSON-LD with alternateName, audience targeting, applicationSubCategory
- Added meta keywords tag covering all target search terms
- Updated llms.txt with persona descriptions and common search terms
- H1 changed to "Domain Security Audit Tool" for stronger SEO signal
- Feature cards expanded with richer descriptions (multi-resolver consensus, key strength analysis, enterprise detection)

### DKIM Validation & Scoring Integration (v26.9.0)
- Comprehensive DKIM selector discovery: 28+ selectors covering major ESPs (Microsoft 365, Google, SendGrid, Mailchimp, etc.)
- Key strength analysis: Detects 1024-bit (weak) vs 2048-bit+ (strong) RSA keys, revoked keys
- Scorecard integration: DKIM with strong keys adds to configured_items and verdict
- Verdict enhancement: "DKIM keys verified with strong cryptography" when applicable

### Consensus Conflict Detection Tests (v26.9.0)
- 7 new negative tests for resolver disagreement scenarios
- Tests majority voting, discrepancy message format, all-different-results edge case
- Deterministic consensus flag behavior verified

### RDAP/DoH Failure Handling Hardening (v26.9.0)
- Explicit per-exception timeout handling in DoH queries (Timeout, ConnectionError, HTTPError)
- Clear "Registry data unavailable" vs "missing" messaging
- Debug/warning logs distinguish service errors from data-not-found

### CAA Reclassification & Fair .gov Scoring (v26.8.3)
- CAA reclassified from "issue" to "optional hardening" (absent_items)
- Missing CAA no longer forces PARTIAL when core controls (DMARC/DNSSEC/SPF) are strong
- .gov domains like usa.gov, whitehouse.gov now correctly show SECURE
- CAA presence adds to configured_items: "CAA (certificate issuance restricted)"
- 90 tests passing (50 unit + 40 integration)

### Multi-Resolver Consensus & Scientific Rigor (v26.8.2)
- Multi-resolver DNS consensus: Queries Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)
- Triangulates results and detects discrepancies between resolvers
- resolver_consensus added to analysis results with per-record consensus info
- **UI display**: "Multi-Resolver Verification" section in DNS Security Analysis shows consensus status
- Redis-backed RDAP cache for multi-worker scaling (shared across workers)
- Structured logging with trace IDs for correlating analysis runs
- Configurable logging level via LOG_LEVEL env var (defaults to INFO for production)
- DMARC p=none correctly classified as issue (no protection, spoofed mail delivered)
- Legacy SPF2.0/pra records labeled as deprecated with RFC 7208 context
- 83 total tests (43 unit + 40 integration) including schema binding tests

### Data Freshness Guarantee
- DNS records are ALWAYS fetched fresh (no caching) for up-to-the-second accuracy
- Only RDAP registry data is cached (6 hour TTL) since it changes rarely
- This ensures users always see current DNS state, not stale cached data

### Redis-Backed Rate Limiter (v26.7.0)
- Hybrid rate limiter: Uses Redis if REDIS_URL is set, falls back to in-memory
- Multi-worker scaling support via shared Redis state
- Atomic operations using Redis sorted sets and pipelines
- Automatic fallback to in-memory on Redis connection errors

### Re-analyze Countdown UX (v26.6.0)
- When rate limited, countdown timer appears on the button instead of redirect
- Results page: Re-analyze button shows "Ready in Xs" countdown in place
- Home page: Analyze button shows countdown when redirected from rate limit
- Static view route `/analysis/{id}/view` for displaying cached results during countdown
- User stays on current page with their data visible while waiting

### Rate Limiting & Abuse Prevention (v26.5.0)
- Per-IP rate limiting: 8 analyses per minute per IP
- 15-second anti-repeat protection (double-click prevention, not caching)
- Every analysis is always fresh - no Force Fresh toggle needed
- RateLimiter class with thread-safe implementation

### Quality Improvements
- Per-section timeouts with partial failure banners
- Analysis timestamp and duration displayed on results page
- RDAP cache extended to 6 hours (registry data only - DNS always fresh)