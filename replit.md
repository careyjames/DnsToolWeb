# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is an OSINT (Open Source Intelligence) platform designed for comprehensive, RFC-compliant domain security analysis. All data is sourced from publicly available intelligence — DNS records, certificate transparency logs, RDAP registrar data, and publicly accessible web resources. It provides immediate and verifiable domain state information, adhering to a "No proprietary magic" philosophy where all conclusions are independently verifiable. Key capabilities include auditing critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Intelligence, and an Email Header Analyzer. The project aims for an open-source model while protecting commercial viability, targeting both technical sysadmins and non-technical executives.

## User Preferences
- Preferred communication style: Simple, everyday language.
- Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets both technical sysadmins and non-technical executives (board-level).
- Memory persistence is critical — `replit.md` is the single source of truth between sessions. Update it every session with decisions, changes, and rationale.
- **IMPORTANT**: If `replit.md` appears truncated or reset, restore from `EVOLUTION.md` which is the persistent backup. Always read BOTH files at session start.
- **CRITICAL**: Read the "Failures & Lessons Learned Timeline" section at the bottom of `EVOLUTION.md` before making any changes. It documents recurring mistakes (CSP inline handlers, font subset issues, PDF title format, print readability) with correct solutions.

## Known Constraints (Read Before Coding)
- **CSP blocks ALL inline handlers**: Never use `onclick`, `onchange`, etc. Use `id` + `addEventListener` in `<script nonce="{{.CspNonce}}">` blocks.
- **PDF filename = `<title>` tag**: Format as "Report Type — domain - DNS Tool" (e.g., "Engineer's DNS Intelligence Report — example.com - DNS Tool").
- **Intelligence document naming** (IC convention — do NOT change without deliberation):
  - Engineer's DNS Intelligence Report (comprehensive, like a National Intelligence Estimate)
  - Executive's DNS Intelligence Brief (concise, like a Presidential Daily Brief / SEIB)
  - "Report" = long detailed document. "Brief" = short decision-maker version. Possessive form = "prepared for you."
  - NOT "Security Intelligence" (that's MI5's name). Use "DNS Intelligence" — specific and on-brand.
  - Must match in ALL locations: `<title>`, print header, screen `<h1>`, OG/Twitter meta tags.
- **Executive print minimum sizes**: Body 11pt, small text 9pt, badges 9pt, labels 8.5pt, metadata 9pt, code 8.5pt, footer 8.5pt. Text-muted color minimum #4b5563. Target audience: 40-50+ year old board members.
- **Executive button**: Uses custom `btn-outline-executive` class (muted gray #9ca3af text, #6b7280 border). NOT btn-outline-light (too bright) or btn-outline-warning (clashes with TLP:AMBER).
- **Button hover style**: ALL report header buttons use translucent hover (rgba at 15% opacity), NOT Bootstrap's default solid fill. Engineer (`btn-outline-info`) overridden with `rgba(13,202,240,0.15)` via `--bs-btn-hover-bg` CSS variable (NOT direct `background-color` — Bootstrap 5 uses CSS custom properties). Executive uses `rgba(156,163,175,0.15)`. Both have 0.2s ease transition.
- **CSS build step**: After editing `static/css/custom.css`, MUST run `npx csso static/css/custom.css -o static/css/custom.min.css`. Server loads `custom.min.css`, not the source file.
- **Font Awesome subset**: 110 glyphs in `static/webfonts/fa-solid-900.woff2`. Verify with fonttools before regenerating. CSS refs in `fontawesome-subset.min.css`.
- **Naming consistency regression check**: When adding any new reference to the intelligence products, always use full canonical names ("Engineer's DNS Intelligence Report" / "Executive's DNS Intelligence Brief"). Never abbreviate to "Engineer's Report" or "Executive's Brief" — the "DNS Intelligence" qualifier is mandatory. Grep for shortened variants before committing. Generic descriptive uses like "executive print reports" (lowercase, not a proper noun) are acceptable.

## System Architecture

### Core System
The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client, DoH fallback, UDP fast-probe for subdomain discovery, three-layer CT+wildcard+DNS subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, SMTP transport verification, CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling, "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation, SMIMEA/OPENPGPKEY detection, `security.txt` detection, AI Surface Scanner (detects `llms.txt`, AI crawler governance, prefilled prompts, CSS-hidden prompt injection), SPF redirect chain handling with loop detection, DNS history timeline via SecurityTrails API, IP Intelligence, OpenPhish integration, Email Header Analyzer with multi-format support (paste, .eml, JSON from Gmail API/Microsoft Graph/Postmark/SendGrid/Mailgun, .mbox, .txt/.log), public exposure checks (secret/credential scanning in page source), expanded exposure checks (opt-in well-known path probing with content validation), and report integrity hash (SHA-256 tamper-evident fingerprint per analysis).
- **Password Manager Compatibility**: API key fields (SecurityTrails, IPinfo.io) use consistent naming (`securitytrails_api_key`, `ipinfo_access_token`), `type="password"`, proper `<label for>` attributes, and custom `autocomplete` section tokens for 1Password/LastPass/Bitwarden save/fill support. No `data-1p-ignore` or `data-lpignore` — fields are designed to be saved by password managers. Labels match provider terminology (SecurityTrails = "API Key", IPinfo.io = "Access Token").
- **Enterprise DNS Detection**: Automatic identification of major enterprise-grade DNS providers and blocklisting of legacy providers.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" for RFC compliance and observation-based language.
- **Remediation Engine**: Generates RFC-aligned "Priority Actions" (fixes) for various DNS records, categorized by severity with DNS record examples.
- **Mail Posture Labels**: Observation-based labels ("Strongly Protected", "Moderately Protected", etc.) aligned with NIST/CISA.
- **Cache Policy**: DNS client cache is disabled for live queries; limited caches are used only for external services.
- **Drift Engine Foundation**: Implements canonical posture hashing to detect configuration drift over time.
- **Licensing**: Uses BSL 1.1 (Business Source License) for both public and private repositories, with a rolling change date to Apache-2.0. The license permits internal use, own-domain audits, and MSP/consultant client audits, while prohibiting hosted/managed competitive offerings.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, full mobile responsiveness, and dual intelligence products (Engineer's DNS Intelligence Report + Executive's DNS Intelligence Brief) with configurable TLP classification (default: TLP:AMBER, aligned with CISA Cyber Hygiene practice). Full FIRST TLP v2.0 hierarchy: RED → AMBER+STRICT → AMBER → GREEN → CLEAR.
- **Dual Intelligence Products**: Engineer's DNS Intelligence Report (full technical detail, `window.print()`) and Executive's DNS Intelligence Brief (condensed board-ready summary, `/analysis/:id/executive`). Both use same live analysis data. Executive template: `results_executive.html`. Engineer button: `btn-outline-info` (translucent hover via CSS variable override). Executive button: custom `btn-outline-executive` class (muted gray, NOT btn-outline-light or btn-outline-warning).
- **Homepage hero hierarchy**: Badge ("DNS Security Intelligence") → H1 ("Domain Security Audit" — SEO anchor) → Tagline ("We answer the BIG questions.") → Subtitle (references both intelligence products) → Protocol tags. The audit is the process; the intelligence products are the output.
- **TLP Policy**: Default TLP:AMBER for all reports (security posture data may reveal actionable vulnerabilities). Full FIRST TLP v2.0 hierarchy in dropdown: RED (recipient only) → AMBER+STRICT (organisation only, §5) → AMBER (organisation and clients) → GREEN (community) → CLEAR (unlimited). FIRST TLP v2.0 colors: RED=#ff2b2b, AMBER=#ffc000, GREEN=#33a532, CLEAR=white/border.
- **TLP CSS specificity rules** (recurring lesson — see EVOLUTION.md): Badge colors in dropdown use `.dropdown-menu .badge.tlp-badge-*` selector. Button colors use `.btn.btn-tlp-*` double-class selector. Both patterns are needed to override Bootstrap's defaults. Dropdown auto-close requires `bootstrap.Dropdown.getInstance(btn).hide()` in the JS click handler (because `e.preventDefault()` blocks Bootstrap's native auto-close).
- **CSS cache-busting**: After CSS edits, MUST: (1) run `npx csso` to minify, (2) bump `AppVersion` in `go-server/internal/config/config.go`, (3) rebuild binary: `cd go-server/cmd/server && go build -o /home/runner/workspace/dns-tool-server .`, (4) restart workflow. The server runs a pre-compiled binary (`main.py` does `os.execvp`), not `go run`, so code changes require explicit rebuild.
- **Pages**: Index, Results, Results Executive, History, Statistics, Compare, Sources, IP Intelligence, Email Header Analyzer, Changelog, Security Policy, Brand Colors (hidden from nav, noindex).
- **Brand Colors Page** (`/brand-colors`): Canonical color reference for design and engineering. Documents brand palette tokens AND standards-aligned cybersecurity colors. TLP v2.0 colors cite FIRST specification directly (formally specified hex values). CVSS severity colors are noted as NVD implementation convention, NOT formal specification — score ranges are FIRST-specified but colors are industry convention. This page must be updated whenever colors change. Not in nav, marked `noindex, nofollow`.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella.
- **IANA RDAP**: For registry data lookups.
- **ip-api.com**: For visitor IP-to-country lookups.
- **crt.sh**: For Certificate Transparency logs.
- **SecurityTrails**: For DNS history timeline (user-provided API key).
- **Team Cymru**: For DNS-based IP-to-ASN attribution.
- **OpenPhish**: For phishing URL feed integration.

### Database
- **PostgreSQL**: Primary database for persistent storage, with separate databases for development and production environments.