# DNS Analysis Tool

## Overview

A web-based DNS intelligence tool providing comprehensive domain record analysis, email security validation (SPF, DMARC, DKIM), and DNS security intelligence reports. The application enables users to analyze domains, view DNS records, check email security configurations, and maintain a history of past analyses with usage statistics. The project's vision is to offer a robust, user-friendly platform for understanding and improving domain and email security posture.

## User Preferences

Preferred communication style: Simple, everyday language.

### Versioning Protocol
When bumping the version, ALL of these must be updated:
1. `APP_VERSION` in `app.py` (line ~18) — this feeds `{{ app_version }}` into all template footers
2. `## Recent Changes` header in `replit.md` — update to new version number
3. Add a new changelog section under `## Recent Changes` in `replit.md`

## System Architecture

### Backend Framework
- **Flask** serves as the web framework.
- **SQLAlchemy** provides ORM functionality.
- **PostgreSQL** is the database for storing domain analysis results.

### Core Components

**Application Entry Points:**
- `main.py` - Simple entry point.
- `app.py` - Main application file containing Flask configuration, database models, and route handlers.

**DNS Analysis Engine:**
- `dns_analyzer.py` - Core DNS analysis logic using `dnspython`.
- Handles domain validation, IDNA encoding, DNS record queries, and email security analysis (SPF, DMARC, DKIM).
- Uses external DNS resolvers (Cloudflare, Google, Quad9, OpenDNS/Cisco Umbrella) with configurable timeouts, ensuring multi-resolver consensus and discrepancy detection.
- Fetches IANA RDAP data for domain registry lookups.
- Performs SMTP Transport Verification (STARTTLS, TLS version, cipher strength, certificate validity).
- Conducts DNS Infrastructure Analysis to detect enterprise DNS providers and suggest alternative security measures.
- Implements comprehensive DKIM selector discovery and key strength analysis (1024-bit vs 2048-bit+).

**Data Model:**
- `DomainAnalysis` model stores analysis results with JSON fields for flexible record storage, tracking DNS records, authoritative records, SPF/DMARC status, and policies. It also includes `country_code` and `country_name` for visitor tracking.

### Frontend Architecture
- Server-rendered HTML templates using Jinja2.
- Bootstrap dark theme for styling, augmented with a native system font stack.
- Font Awesome icons are self-hosted and subsetted for performance.
- Custom CSS (`static/css/custom.min.css`) and client-side JavaScript (`static/js/main.js`) for UI/UX enhancements.

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
- MVC-style separation with Flask routes, SQLAlchemy models, and Jinja2 templates.
- Singleton pattern for the `DNSAnalyzer` instance.
- JSON columns in PostgreSQL for variable-structure data.

### Quality of Life & Performance
- Critical inline CSS for instant first paint.
- Preconnect hints for external resources.
- Per-IP rate limiting (8 analyses per minute) with a Redis-backed, fall-back-to-in-memory solution.
- Re-analyze countdown UI for improved user experience during rate limiting.
- Data Freshness: DNS records are always fetched fresh; only RDAP data is cached (6-hour TTL).
- SEO optimization through multi-persona keywords, rich schema, and enhanced meta tags.

## External Dependencies

### Python Packages
- **Flask**: Web framework.
- **Flask-SQLAlchemy**: Database ORM integration.
- **dnspython**: DNS query library.
- **requests**: HTTP client for external API calls.
- **idna**: Internationalized domain name encoding.

### External Services
- **Cloudflare DNS (1.1.1.1)**: Primary consensus resolver.
- **Google Public DNS (8.8.8.8)**: Consensus resolver.
- **Quad9 (9.9.9.9)**: Consensus resolver.
- **OpenDNS/Cisco Umbrella (208.67.222.222)**: Consensus resolver.
- **IANA RDAP**: Registry data for domain information lookups.
- **ip-api.com**: Free IP-to-country lookup service.

### Frontend CDN Resources
- Bootstrap dark theme CSS (initially, now partially self-hosted).
- Font Awesome icons (now self-hosted and subsetted).

### Database
- PostgreSQL (Replit-managed).

### Testing
- **pytest**: Unit and integration test framework.

## Recent Changes (v26.10.21)

### Security Gateway DKIM Attribution & SPF Evidence Hierarchy (v26.10.21)
- When MX points to a security gateway (Proofpoint, Mimecast) but SPF includes a different sending platform (Microsoft 365, Google Workspace), the tool now correctly treats the SPF platform as the primary for DKIM purposes
- Previously: cisa.gov showed "DKIM verified for Microsoft 365 only — no DKIM found for primary mail platform (Proofpoint)" — false warning because Proofpoint is the inbound gateway, not the DKIM signer
- Now: cisa.gov correctly shows DKIM as "Found" (success) with M365 selector, plus info box explaining the gateway architecture
- `_detect_primary_mail_provider` returns `{provider, gateway}` dict instead of string — gateway is populated when MX is a known security gateway with a different SPF-detected sender
- Blue info box in results explains: "Mail routed through Proofpoint (security gateway) — DKIM signed by Microsoft 365 (sending platform). This is a standard enterprise architecture."
- Verdict text includes gateway context: "DKIM keys verified with strong cryptography (signed by Microsoft 365 via Proofpoint gateway)"
- `SECURITY_GATEWAYS` set: Proofpoint, Mimecast, Barracuda, Perception Point, Sophos, FireEye, Trend Micro, Forcepoint, Symantec, Hornetsecurity, SpamExperts
- Federal compliance context for SPF -all updated to be precise: BOD 18-01 "requires valid SPF records" — doesn't explicitly specify -all vs ~all; -all is widespread federal practice, not spelled-out requirement
- SPF provider detection split into `SPF_MAILBOX_PROVIDERS` (M365, Google, Zoho, Fastmail, ProtonMail) and `SPF_ANCILLARY_SENDERS` (SendGrid, Mailchimp, Mailgun, etc.) — mailbox providers always checked first regardless of include order in SPF record
- FAQ #9 updated with precise BOD 18-01 findings: directive requires "valid SPF records" but doesn't explicitly mandate -all vs ~all

### DMARC-Aware SPF Messaging & Authority-Backed Guidance (v26.10.20)
- SPF `~all` (soft fail) badge changed from yellow/warning to green — it's the industry standard used by Google, Apple, and most providers
- SPF `~all` message now reads "industry-standard soft fail" instead of implying a weakness
- New blue educational info box for `~all` domains cites CISA BOD 18-01 and RFC 7489 §10.1, explaining DMARC is the primary enforcement control
- New yellow warning info box for `-all` domains explains RFC 7489 §10.1 conflict: hard fail can cause rejection before DKIM/DMARC evaluation
- Both boxes provide DMARC-context-aware guidance (different messages for reject, quarantine, none, or missing DMARC)
- Microsoft called out as the notable exception that historically defaults to `-all`
- `~all + DMARC reject` identified as the strongest compatible security stance per CISA and RFC guidance
- No-mail domains (`v=spf1 -all` with no senders) excluded from the `-all` warning — hard fail is correct for parked domains
- `.gov` domain detection: federal domains show "Federal compliance context" with landmark icon acknowledging BOD 18-01; `-all` recommendation suppressed for `.gov` since they follow a binding directive
- FAQ #9 added: "I thought SPF -all was the strongest protection. Isn't ~all weaker?" — covers RFC 7489 §10.1, federal .gov context, CISA BOD 18-01 history, and Microsoft exception
- **Key research finding (BOD 18-01 text):** The directive requires "valid SPF records" and DMARC p=reject, but does NOT explicitly mandate `-all` vs `~all`. Federal `-all` is widespread practice (defense-in-depth), not a spelled-out requirement. In 2017 when BOD 18-01 was issued, 80%+ of federal domains had no DMARC, so `-all` was a pragmatic safety net. Now that DMARC p=reject is deployed, `-all` is redundant but federal infrastructure is controlled enough that the RFC 7489 §10.1 risk is lower. The directive hasn't been updated to reflect the industry consensus around `~all + DMARC reject`.

### Context-Aware DKIM Selector Attribution (v26.10.19)
- DKIM selector names like `selector1`/`selector2` no longer falsely attributed to Microsoft 365 when MX records show self-hosted email
- Apple.com was incorrectly showing "Microsoft 365" badge on DKIM selectors — now shows no provider badge (self-hosted)
- Added `iphmx` as Proofpoint MX pattern (previously only `pphosted` was detected)
- Deloitte (Proofpoint via iphmx.com) now correctly shows "Proofpoint (inferred)" on ambiguous selectors
- Ambiguous selectors (`selector1`, `selector2`, `s1`, `s2`, `k1`, `k2`, `default`) are only attributed to their "known" provider when MX confirms that provider
- SPF includes are authoritative evidence of sending platform: `include:spf.protection.outlook.com` is a definitive declaration of M365 usage, not a hint. SPF is the stronger signal for DKIM attribution since DKIM is signed by the sending platform, not the inbound gateway. MX is used as primary signal for efficiency when it matches a known mailbox provider.
- `analyze_dkim` now fetches its own MX and SPF data for provider detection rather than relying on externally passed data

### Self-Hosted Enterprise DNS & Provider Expansion (v26.10.17)
- Self-hosted enterprise DNS detection now synced to hosting summary card (Apple, Meta, Intel, Salesforce, Cisco)
- Previously, infrastructure analysis detected self-hosted enterprises but the DNS Hosting card showed "Standard"
- Added Com Laude DNS (`comlaude-dns`) and BT/British Telecom (`bt.net`) to both detection lists
- Added Oracle Cloud DNS, F5 Distributed Cloud, Verizon Business DNS, AT&T Managed DNS, CSC Global, MarkMonitor to enterprise provider detection (v26.10.16)
- Multi-provider DNS: majority-match logic picks provider with most nameservers as primary

### DKIM Provider Inference (v26.10.15)
- Unattributed DKIM selectors (e.g., `dkim._domainkey`, `email._domainkey`) are now inferred as belonging to the primary mail provider when standard named selectors aren't found
- Fixes false "not verified for Proofpoint" warnings for enterprises like IBM that use custom DKIM selector names
- Inferred selectors display "(inferred)" badge in results UI
- DKIM posture moves from "Monitoring" to "Configured" when inference succeeds
- Verdict text explains the inference for transparency

### Documentation & Branding Update (v26.10.14)
- Updated all FAQ schema and visible FAQ content to reference 4 resolvers (Cloudflare, Google, Quad9, OpenDNS)
- "How is this different" FAQ answer now lists all 4 consensus resolvers

### 4-Resolver Consensus & Branding (v26.10.13)
- Added OpenDNS/Cisco Umbrella (208.67.222.222) as 4th consensus resolver
- Multi-resolver consensus now queries Cloudflare, Google, Quad9, and OpenDNS in parallel
- ThreadPoolExecutor increased to 4 workers for parallel resolver queries
- Owl of Athena branding: optimized PNG (5.6KB) added to all page footers
- Footer added to history and statistics pages (previously missing)
- OG image fix: Cross-Origin-Resource-Policy set to cross-origin for /static/images/

### System Font Stack & Performance (v26.10.12)
- Native system font stack: SF Pro, Segoe UI, Roboto
- Preconnect hints and critical inline CSS on all pages
- Lighthouse: Performance 94%, Accessibility 100%, Best Practices 100%, SEO 100%