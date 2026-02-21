# DNS Tool — Domain Security Audit

## Overview
This project is an OSINT platform designed for RFC-compliant domain security analysis. It aims to provide comprehensive insights into domain security postures, offering both technical and executive-level reports. The platform focuses on identifying vulnerabilities and misconfigurations using best practices and recognized standards. The business vision is to deliver a robust, high-quality tool for security researchers and organizations to audit and enhance their domain security, with market potential in cybersecurity and compliance sectors.

## User Preferences
- **Development Process**: Research the best-practices path first (cite RFCs, standards). Design before implementing. Write tests first. Check quality gates during development, not after. The tests, quality gates, and documentation exist to prevent rework — use them.
- **Quality Gates**:
    - Lighthouse Performance: 98–100 acceptable
    - Lighthouse Best Practices, Accessibility, SEO: 100
    - Observatory: 130 (never decrease)
    - SonarCloud Reliability, Security, Maintainability: A (zero new bugs, vulnerabilities, code smells)
- **Code Changes**: After ANY Go code changes, run `go test ./go-server/... -count=1`. After CSS changes, run `npx csso static/css/custom.css -o static/css/custom.min.css`.
- **Version Bumps**: Update `AppVersion` in `go-server/internal/config/config.go` for any new release. For iterative CSS changes, bump `Version` in `config.go` each iteration to bust browser cache.
- **Security**: No inline onclick/onchange/style="". Use addEventListener in nonce'd script blocks.
- **UI/UX**: Every CSS/template change must be verified at 375px width. Buttons need `white-space: nowrap`. Never apply `pointer-events: none` to `body` or `html`.
- **Claims**: Every claim must be backed by implemented code. Use "on the roadmap" for future items.
- **Capitalization**: NIST/Chicago title case for all user-facing headings, badges, trust indicators. Never camelCase in UI copy.
- **Print-only elements**: ALL print-only elements MUST have `display: none !important` in the screen stylesheet.
- **Critical Rules (Summary)**:
    1. **After ANY Go code changes**: Run `go test ./go-server/... -count=1` before considering work done.
    2. **After CSS changes**: Run `npx csso static/css/custom.css -o static/css/custom.min.css` — **server loads minified file only; skip this and changes won't appear**
    3. **Version bumps**: Update `AppVersion` in `go-server/internal/config/config.go`
    4. **Build**: `./build.sh` compiles to `./dns-tool-server`; `main.py` is the gunicorn trampoline.
    5. **CSP**: No inline onclick/onchange/style="". Use addEventListener in nonce'd script blocks.
    6. **Safari scan navigation**: NEVER use `location.href` to start a scan that shows an overlay with timer/phases — WebKit kills running JS on navigation, freezing the overlay at 0s. Use `fetch()` + `document.write()` + `history.replaceState()` instead. Always call `showOverlay()` (double-rAF animation restart) before starting the fetch. After `document.close()`, always call `globalThis.scrollTo(0, 0)` to reset scroll position. Pattern: main.js, results.html, history.html, dossier.html.
    7. **SecurityTrails**: User-key-only. NEVER call automatically. 50 req/month hard limit.
    8. **Reality Check**: Every claim must be backed by implemented code. Use "on the roadmap" for future items.
    9. **Font Awesome**: WOFF2 subset only. Check CSS rule exists before using new icons.
    10. **Stubs**: `_oss.go` files return safe non-nil defaults, never errors.
    11. **Capitalization**: NIST/Chicago title case for all user-facing headings, badges, trust indicators. Never camelCase in UI copy.
    12. **pointer-events**: NEVER apply `pointer-events: none` to `body` or `html` — kills Chrome wheel/trackpad scroll. Use targeted selectors on interactive elements instead.
    13. **Print-only elements**: ALL print-only elements (`.print-report-header`, `.print-domain-banner`, `.print-report-footer`) MUST have `display: none !important` in the screen stylesheet. They are shown via `display: block !important` inside `@media print`. Without the screen hide rule, `document.write()` loads show the print header on screen (the CSS race condition). Never add print-only template content without a corresponding screen hide rule.
    14. **Mobile verification**: EVERY CSS/template change must be verified at 375px width. Buttons need `white-space: nowrap`. No `flex: 1` + `min-width: 0` on buttons without `nowrap`. See DOD.md "Mobile UI Verification" checklist.
    15. **CSS cache busting**: When making iterative CSS changes, bump `Version` in config.go EACH iteration — the browser caches `custom.min.css?v=VERSION` aggressively. Same version = stale CSS in Replit preview. Always bump before asking user to evaluate visual changes.
    16. **Homepage ICAE hero card**: Structure is `div.icae-hero-card` → `a.icae-hero-statement` (the confidence statement) + `div.icae-hero-protocols` (protocol badges). Statement and protocols are SEPARATE blocks with a `border-top` divider. Protocols use the existing `.icae-badge` pill buttons. Do NOT flatten protocols into inline text — the pill badges are the approved design. Do NOT use `<span>` for block layout — use `<div>` elements (or `display:block` on `<a>`) to guarantee block stacking.

## System Architecture
The application features a Go/Gin backend for high performance and a Bootstrap dark theme frontend for a consistent user experience. A PostgreSQL database is used for data persistence. The project follows an open-core architecture with a BSL 1.1 license.

**UI/UX Decisions:**
- **Frontend Framework**: Bootstrap for responsive design and theming.
- **Theming**: Dark theme with specific color palettes for standard and "Covert Mode" views.
- **Interactive Elements**: CSP-compliant JavaScript with `addEventListener` for security.
- **Reporting**: "Engineer's DNS Intelligence Report" (technical) and "Executive's DNS Intelligence Brief" (board-ready) templates.
- **Mobile First**: All UI changes are verified at 375px width.
- **Covert Mode**: A tactical red-light theme (`body.covert-mode`) toggleable via a navbar icon, persisting via `localStorage`. It features deeper backgrounds and crimson/oxblood accents, maintaining accessibility. Status/severity badge colors remain unchanged. A separate `results_covert.html` template provides a red team/adversarial perspective.
- **Architecture Page**: Interactive Mermaid diagrams for system visualization.

**Technical Implementations & Design Choices:**
- **Backend**: Go/Gin for API and server-side logic.
- **Database**: PostgreSQL.
- **Authentication**: Google OAuth 2.0 with PKCE (S256), implemented using pure standard library, supporting Advanced Protection. Security hardening includes OIDC nonce for replay protection, `iat` validation with 5-minute clock skew tolerance, 10-second HTTP client timeouts on token/userinfo requests, and SameSite=Lax on all auth cookies. Admin bootstrapping is a one-time process.
- **Admin Panel**: Session management dashboard with per-user session counts (active/total), purge expired sessions, per-user session reset, and user deletion (admin deletion blocked). All admin actions protected with CSRF tokens.
- **Site Analytics**: Privacy-preserving analytics middleware using IP+User-Agent fingerprinting with daily-rotating SHA-256 salt (no cookies, no PII). Incremental flush every 60 seconds with additive SQL merge for accurate counts across server restarts.
- **Ephemeral Scan**: A `/dev/null Scan` option allows full analysis without persistence, skipping all data recording and analytics.
- **Content-Usage Directive Detection**: Implements a parser for `Content-Usage:` directives in `robots.txt`, aligned with an active IETF draft for AI governance signals.
- **SMTP Probe Infrastructure**: Supports both local and remote SMTP probing. Remote probing uses a dedicated external API with shared-secret authentication and rate limiting, providing multi-port probing and banner capture.
- **Misplaced DMARC Detection**: Post-analysis enrichment scans root TXT records for v=DMARC1 patterns incorrectly published at the domain apex instead of the _dmarc subdomain (RFC 7489 §6.1). Surfaces misconfiguration with remediation guidance. Four deterministic golden test cases.
- **Engines**:
    - **ICIE (Intelligence Classification & Interpretation Engine)**: Handles analysis logic, including post-analysis enrichment (misplaced DMARC detection).
    - **ICAE (Intelligence Confidence Audit Engine)**: Tracks accuracy with 114 deterministic test cases across 9 protocols (SPF 18, DMARC 18, DNSSEC 24, DKIM 8, DANE 12, MTA-STS 11, TLS-RPT 5, BIMI 9, CAA 9). Five-tier maturity model: Development → Verified → Consistent → Gold → Gold Master.
- **Code Structure**: Utilizes Go build tags (`intel` for private features, `!intel` for public OSS stubs) and a repository mirroring strategy.
- **CI/CD**: SonarCloud for code quality, GitHub Actions for Codeberg mirroring, and Forgejo Actions for redundancy.
- **Origin Story Page**: /about page with authentic timeline (Memphis 1980 → Nashville IT → Raspberry Pi → PhreakNIC → Hak5 → Python CLI → Go platform). Includes acknowledgments with verifiable linked references.
- **Homepage ASCII Hero**: Unicode block-character art title on desktop with automatic mobile text fallback below 768px.

## External Dependencies
- **Google OAuth 2.0**: For user authentication.
- **SecurityTrails**: Third-party API for domain intelligence (usage is user-key-only and rate-limited).
- **`codeberg.org/miekg/dns`**: Go DNS library (v0.6.52).
- **`probe-us-01.dns-observe.com`**: External API endpoint for remote SMTP probing.
- **Font Awesome**: For icons (WOFF2 subset only).
- **SonarCloud**: For continuous code quality and security analysis.
- **GitHub**: Canonical repository hosting.
- **Codeberg**: Read-only mirror repository hosting.