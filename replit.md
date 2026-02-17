# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is an OSINT platform for comprehensive, RFC-compliant domain security analysis. It uses publicly available intelligence (DNS records, certificate transparency logs, RDAP data, web resources) to provide immediate, verifiable domain state information. Key capabilities include auditing critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Intelligence, and an Email Header Analyzer. The project aims for an open-source model while protecting commercial viability, targeting both technical sysadmins and non-technical executives.

## User Preferences
- Preferred communication style: Simple, everyday language.
- Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets technical sysadmins, non-technical executives (board-level), and the InfoSec/security research community (red teams, pen testers, bug bounty hunters).
- Memory persistence is critical — `replit.md` is the single source of truth between sessions. Update it every session with decisions, changes, and rationale.
- **IMPORTANT**: If `replit.md` appears truncated or reset, restore from `EVOLUTION.md` which is the persistent backup. Always read BOTH files at session start.
- **CRITICAL**: Read the "Failures & Lessons Learned — Detailed Analysis" section in `EVOLUTION.md` before making any changes. It documents recurring mistakes (CSP inline handlers, font subset issues, PDF title format, print readability) with correct solutions.
- **REALITY CHECK RULE (v26.19.20)**: Every homepage claim, schema statement, and documentation assertion must be backed by implemented code. Do NOT claim features that are stubs or planned. Use language like "on the roadmap" for future items, "context" instead of "verification" for informational features (e.g., MPIC).

## System Architecture

### Core System
The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation. The build process uses `./build.sh` which compiles to `./dns-tool-server`, and `main.py` acts as a gunicorn trampoline to launch the Go binary. All Go and CSS changes require rebuilding and restarting the workflow.

### Backend
The backend utilizes Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS queries. Key features include a multi-resolver DNS client with DoH fallback, three-layer subdomain discovery, posture scoring with CVSS-aligned risk levels, a concurrent orchestrator, Mail Transport Security assessment, CSRF middleware, rate limiting, SSRF hardening, telemetry, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation, SMIMEA/OPENPGPKEY detection, `security.txt` detection, an AI Surface Scanner (detecting `llms.txt`, AI crawler governance, prefilled prompts, CSS-hidden prompt injection), SPF redirect chain handling with loop detection, DNS history timeline, IP Intelligence, OpenPhish integration, an Email Header Analyzer, public exposure checks, expanded exposure checks, and a report integrity hash. The system includes Enterprise DNS Detection and adheres to an "Analysis Integrity Standard" for RFC compliance. A Remediation Engine generates RFC-aligned "Priority Actions". The Intelligence Classification and Interpretation Engine (ICIE) formalizes how multiple intelligence sources are cross-referenced, ranked, classified, and interpreted. The project uses the BSL 1.1 license for both public and private repositories.

### Frontend
The frontend uses server-rendered HTML with Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript, supporting PWA, accessibility, and full mobile responsiveness. It generates dual intelligence products: an Engineer's DNS Intelligence Report (technical detail) and an Executive's DNS Intelligence Brief (board-ready summary), both with configurable FIRST TLP v2.0 classification (default: TLP:AMBER). Each section and protocol card features a plain-language question with a data-driven badge answer.

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
- **PostgreSQL**: Primary database for persistent storage, with analysis data being immutable and append-only to ensure auditable records.

## Two-Repo Build-Tag Architecture (refactored 2026-02-17)
The project uses a two-repository design with Go build tags (`//go:build intel` / `//go:build !intel`):
- **DNS Tool Web** (public): Full application framework + `_oss.go` stubs (empty maps, safe defaults)
- **dnstool-intel** (private): `_intel.go` files with proprietary provider databases, detection patterns, advanced analysis

### Three-File Pattern
Each intelligence boundary uses three files:
- `<name>.go` — Framework (types, constants, utilities). No build tag. Always compiled.
- `<name>_oss.go` — `//go:build !intel`. Empty stubs. Ships in public repo.
- `<name>_intel.go` — `//go:build intel`. Full intelligence. Private repo only.

### Build Commands
- **OSS edition**: `go build ./go-server/cmd/server/` (default, no tag)
- **Full edition**: `go build -tags intel ./go-server/cmd/server/` (with private repo overlaid)

### Stub Contract
Every `_oss.go` stub MUST: (1) return safe non-nil defaults, (2) never return errors, (3) maintain exact function signatures matching `_intel.go`, (4) allow UI to render gracefully.

### Current Stub Files (11 boundary files, each split into 3)
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

### Pure Framework Files (no split needed)
`confidence.go`, `dkim_state.go` — types and constants only, no intelligence data.

### Fully Implemented Framework (no stubs)
`commands.go` (19 protocol sections, 25+ verification commands)

### Intel Transfer Status (completed 2026-02-17)
All 11 `_intel.go` files have been transferred to `careyjames/dnstool-intel` private repo. `docs/intel-staging/` has been deleted from the public repo. No intelligence data remains in the public repo.

### Python Files (Not Stubs, Not Runtime)
- `main.py` — Process trampoline only (os.execvp replaces Python with Go binary)
- `go-server/scripts/audit_icons.py` — Dev-only Font Awesome audit helper

## Documentation & Citation Standard (decided 2026-02-17)

### Official Standard: NIST SP 800-series Style
All documentation, reports, and output follow NIST Special Publication 800-series conventions, augmented with IEEE-style numeric citations for RFC/protocol references.

### Why NIST
- Aligns with existing NIST/CISA/RFC ecosystem the tool operates within
- Reads authoritative for both executives and technical users
- Matches the security operations and intelligence community voice
- Natural fit for the "Decision-Ready Intelligence" framing
- Avoids academic tone (APA/Chicago) and humanities feel that would undermine security credibility
- More appropriate than ICD (Intelligence Community Directives) which implies government classification handling beyond our scope

### Style Rules
1. **Document structure**: Summary → Findings → Evidence → Impact → Recommendations (mirrors NIST SP 800-53, 800-171)
2. **Tone**: Authoritative, observation-based, factual. No hedging language. Direct statements of observed state.
3. **Technical references**: IEEE-style numbered citations for RFCs, NIST SPs, and protocol standards (e.g., [1] RFC 7489, [2] NIST SP 800-177)
4. **Terminology**: Use NIST/CISA vocabulary — "control", "finding", "observation", "recommendation", "risk level" — not academic terms like "hypothesis" or "methodology"
5. **Report titles**: Use intelligence-community format: "DNS Intelligence Report" / "DNS Intelligence Brief" (not "Analysis" or "Study")
6. **Visual identity**: Dark theme with hacker-culture fonts is fine — the NIST standard governs content structure and citation format, not visual design
7. **TLP classification**: Already using FIRST TLP v2.0 — this remains the classification framework