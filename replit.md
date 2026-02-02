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
- Test files: `tests/test_dns_analyzer.py` (28 unit tests), `tests/test_integration.py` (33 integration tests)
- Run tests: `python -m pytest tests/ -v`
- Total: 61 tests covering routes, rate limiting, scorecard logic, error states

## Recent Changes (v26.8.0)

### Multi-Resolver Consensus & Scientific Rigor (v26.8.0)
- Multi-resolver DNS consensus: Queries Cloudflare (1.1.1.1), Google (8.8.8.8), Quad9 (9.9.9.9)
- Triangulates results and detects discrepancies between resolvers
- resolver_consensus added to analysis results with per-record consensus info
- **UI display**: "Multi-Resolver Verification" section in DNS Security Analysis shows consensus status
- Redis-backed RDAP cache for multi-worker scaling (shared across workers)
- Structured logging with trace IDs for correlating analysis runs
- Configurable logging level via LOG_LEVEL env var (defaults to INFO for production)
- 80 total tests (40 unit + 40 integration)

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