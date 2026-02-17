# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is an OSINT platform for comprehensive, RFC-compliant domain security analysis. It uses publicly available intelligence (DNS records, certificate transparency logs, RDAP data, web resources) to provide immediate, verifiable domain state information. Key capabilities include auditing critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Intelligence, an Email Header Analyzer (with subject line scam detection, third-party spam vendor integration, and homoglyph analysis), and posture drift detection foundation. The project aims for an open-source model while protecting commercial viability, targeting both technical sysadmins and non-technical executives.

## User Preferences
- Preferred communication style: Simple, everyday language.
- Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets technical sysadmins, non-technical executives (board-level), and the InfoSec/security research community (red teams, pen testers, bug bounty hunters).
- Memory persistence is critical — `replit.md` is the single source of truth between sessions. Update it every session with decisions, changes, and rationale.
- **IMPORTANT**: If `replit.md` appears truncated or reset, restore from `EVOLUTION.md` which is the persistent backup. Always read BOTH files at session start.
- **CRITICAL**: Read the "Failures & Lessons Learned — Detailed Analysis" section in `EVOLUTION.md` before making any changes. It documents recurring mistakes (CSP inline handlers, font subset issues, PDF title format, print readability) with correct solutions.
- **MANDATORY POST-EDIT RULE**: After ANY Go code changes, run `go test ./go-server/... -count=1` before considering the work done. This runs the boundary integrity tests that catch intelligence leaks, stub contract breakage, duplicate symbols, and architecture violations. Regressions cost $100-200/day — never skip this step.
- **REALITY CHECK RULE (v26.19.20)**: Every homepage claim, schema statement, and documentation assertion must be backed by implemented code. Do NOT claim features that are stubs or planned. Use language like "on the roadmap" for future items, "context" instead of "verification" for informational features (e.g., MPIC).
- **BREADCRUMBS**: `EVOLUTION.md` is the project's permanent breadcrumb trail — every session's decisions, changes, lessons, and rationale. `replit.md` is the quick-reference config. Both must be updated every session. If `replit.md` resets, restore from `EVOLUTION.md`.

## System Architecture

### Core System
The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation. The build process uses `./build.sh` which compiles to `./dns-tool-server`, and `main.py` acts as a gunicorn trampoline to launch the Go binary. All Go and CSS changes require rebuilding and restarting the workflow.

### Backend
The backend utilizes Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS queries. Key implemented features:
- Multi-resolver DNS client with DoH fallback and high-speed UDP probing
- Three-layer subdomain discovery (CT logs + wildcard detection + DNS probing ~140 common names)
- Posture scoring with CVSS-aligned risk levels
- Concurrent orchestrator with independent contexts per task
- Mail Transport Security (three-tier: policy/telemetry/probe, RFC 8461/7672 aligned)
- CSRF middleware, rate limiting, SSRF hardening, telemetry
- DMARC external reporting authorization, dangling DNS/subdomain takeover detection
- HTTPS/SVCB intelligence, IP-to-ASN attribution (Team Cymru), Edge/CDN vs origin detection
- SaaS TXT footprint extraction, CDS/CDNSKEY, SMIMEA/OPENPGPKEY, security.txt detection
- AI Surface Scanner (llms.txt, AI crawler governance, prefilled prompts, CSS-hidden prompt injection)
- SPF redirect chain handling with loop detection, SPF provider detection with MX corroboration
- DKIM gateway inference pipeline (detects mailbox provider behind security gateways)
- DNS history timeline, IP Intelligence page
- OpenPhish phishing URL feed integration
- Email Header Analyzer: SPF/DKIM/DMARC verification, multi-format (.eml/.json/.mbox/.txt), third-party spam vendor detection (Proofpoint/Barracuda/Microsoft SCL/Mimecast), subject line scam analysis (phone numbers/payment amounts/homoglyphs/scam phrases), brand mismatch with homoglyph normalization, BCC detection, educational "Understanding This Attack" callout
- Public exposure checks, expanded exposure checks (opt-in)
- Report integrity hash (SHA-256), posture hash for drift detection
- Enterprise DNS Detection, Analysis Integrity Standard, Remediation Engine ("Priority Actions")
- ICIE (Intelligence Classification and Interpretation Engine)
- Per-section maintenance tags system
- BSL 1.1 license for both public and private repositories

### Frontend
Server-rendered HTML with Go html/template, Bootstrap dark theme, custom CSS, client-side JavaScript. PWA, accessibility, mobile responsive. Dual intelligence products: Engineer's DNS Intelligence Report (technical) and Executive's DNS Intelligence Brief (board-ready), both with configurable FIRST TLP v2.0 (default: TLP:AMBER). Plain-language questions with data-driven badge answers. Big Questions for critical thinking.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella
- **IANA RDAP**: Registry data lookups (multi-endpoint, parallel attempts, exponential backoff)
- **ip-api.com**: Visitor IP-to-country lookups
- **crt.sh**: Certificate Transparency logs (independent 10s context)
- **SecurityTrails**: DNS history and IP Intelligence (user-provided API key ONLY; 50 req/month hard limit; NEVER call automatically)
- **Team Cymru**: DNS-based IP-to-ASN attribution (independent 8s context)
- **OpenPhish**: Phishing URL feed (Email Header Analyzer body scanning)

### Database
- **PostgreSQL**: Immutable, append-only analysis data with posture_hash and integrity_hash columns

## Two-Repo Build-Tag Architecture
Two-repository design with Go build tags (`//go:build intel` / `//go:build !intel`):
- **DNS Tool Web** (public): Full framework + `_oss.go` stubs (empty maps, safe defaults)
- **dnstool-intel** (private): `_intel.go` files with proprietary provider databases

### Three-File Pattern
- `<name>.go` — Framework (types, constants, utilities). No build tag.
- `<name>_oss.go` — `//go:build !intel`. Empty stubs. Public repo.
- `<name>_intel.go` — `//go:build intel`. Full intelligence. Private repo only.

### Build Commands
- **OSS**: `go build ./go-server/cmd/server/` (default, no tag)
- **Full**: `go build -tags intel ./go-server/cmd/server/`

### Stub Contract
Every `_oss.go` stub MUST: (1) return safe non-nil defaults, (2) never return errors, (3) maintain exact function signatures, (4) allow UI to render gracefully.

### Current Stub Files (11 boundary files)
| File | OSS Stub | Intel Location |
|---|---|---|
| `edge_cdn` | `edge_cdn_oss.go` | `dnstool-intel` |
| `saas_txt` | `saas_txt_oss.go` | `dnstool-intel` |
| `infrastructure` | `infrastructure_oss.go` | `dnstool-intel` |
| `providers` | `providers_oss.go` | `dnstool-intel` |
| `ip_investigation` | `ip_investigation_oss.go` | `dnstool-intel` |
| `manifest` | `manifest_oss.go` | `dnstool-intel` |
| `ai_surface/http` | `http_oss.go` | `dnstool-intel` |
| `ai_surface/llms_txt` | `llms_txt_oss.go` | `dnstool-intel` |
| `ai_surface/robots_txt` | `robots_txt_oss.go` | `dnstool-intel` |
| `ai_surface/poisoning` | `poisoning_oss.go` | `dnstool-intel` |
| `ai_surface/scanner` | `scanner_oss.go` | `dnstool-intel` |

### Boundary Integrity Test Suite
- `go-server/internal/analyzer/boundary_integrity_test.go` — 6 analyzer boundaries
- `go-server/internal/analyzer/ai_surface/boundary_integrity_test.go` — 5 ai_surface boundaries
- Run: `go test ./go-server/... -count=1`

## Known Constraints & Critical Rules

### Build and Deploy
- CSS minification: After editing custom.css, MUST run `npx csso static/css/custom.css -o static/css/custom.min.css`
- AppVersion bump: After CSS/Go changes, bump `AppVersion` in `config.go` to bust caches
- Binary path: `main.py` does `os.execvp("./dns-tool-server", ...)` — compile to `./dns-tool-server`

### Frontend
- CSP inline handlers: CSP blocks ALL inline onclick/onchange/onsubmit. Use id + addEventListener in nonce'd script blocks.
- CSP inline styles: Inline style="" blocked. Use CSS utility classes.
- Safari overlay animation: Every classList.remove('d-none') on animated overlays MUST use showOverlay() — WebKit doesn't restart CSS animations from display:none.
- Font Awesome subset: WOFF2 subset, not full FA. Check CSS rule exists before using icons.
- DOM safety: createElement + textContent + appendChild. Never innerHTML with dynamic data.
- Executive print: Minimum body 11pt, small 9pt, code 8.5pt. Nothing below 8pt.
- Bootstrap overrides: Override --bs-btn-* CSS variables, NOT direct background-color.

### Data and API
- SecurityTrails: User-key-only. NEVER call automatically. 50 req/month hard limit.
- RDAP: Tier 4 contextual — failure is NOT a security analysis error.
- OSINT positioning: Explicitly OSINT. NOT pen test, NOT PCI ASV, NOT vulnerability assessment.

### Stub Architecture
- Default principle: Stubs produce LEAST incorrect advice.
- Key defaults: isHostedEmailProvider() -> true, isBIMICapableProvider() -> false, isKnownDKIMProvider() -> false

### SEO
- Analysis pages: noindex, nofollow (ephemeral). No canonical.
- Compare pages: noindex (dynamic).
- Only static feature pages indexable.

## Intelligence Document Naming
- **Engineer's DNS Intelligence Report** — Comprehensive technical. "Report" = detailed all-source.
- **Executive's DNS Intelligence Brief** — Concise board-ready. "Brief" = decision-maker version.
- **Possessive form**: "Engineer's"/"Executive's" = "prepared for you"
- **"DNS Intelligence"** not "Security Intelligence" (MI5's name)

## Documentation Files
| File | Purpose |
|------|---------|
| `replit.md` | Agent memory / project context (may reset) |
| `EVOLUTION.md` | Permanent breadcrumb trail — backup for replit.md |
| `DOCS.md` | Technical documentation |
| `DOD.md` | Definition of Done checklist |
| `LICENSING.md` | Plain-language BSL 1.1 explanation |
| `LICENSE` | Legal license text (BSL 1.1) |
| `DRIFT_ENGINE.md` | Drift detection roadmap (4 phases) |
| `INTELLIGENCE_ENGINE.md` | ICIE framework |
| `docs/FEATURE_INVENTORY.md` | Public feature list |
| `docs/BOUNDARY_MATRIX.md` | Symbol analysis |
| `docs/BUILD_TAG_STRATEGY.md` | Build-tag strategy, CI matrix |

## Future Roadmap
- Drift Engine Phases 2-4 (compare, timeline UI, alerting) — see DRIFT_ENGINE.md
- Globalping.io: Distributed DNS resolution probes (complementary to port 25 probe, NOT replacement)
- External VPS probe nodes: Hetzner/OVH for SMTP port 25 probing
- Homebrew distribution for macOS/Linux CLI
- Zone file export/import for offline analysis
- Raw intelligence API access
- ISC recommendation path integration
- One-liner verification commands
- Email Header Analyzer feature matrix
- Probe node integration in analysis pipeline
