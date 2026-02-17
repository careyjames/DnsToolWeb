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