# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It provides immediate and verifiable domain state information, adhering to a "No proprietary magic" philosophy where all conclusions are independently verifiable. Key capabilities include auditing critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Investigation, and an Email Header Analyzer. The project aims for an open-source model while protecting commercial viability, targeting both technical sysadmins and non-technical executives.

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
- **PDF filename = `<title>` tag**: Format as "Report Type — domain - DNS Tool" (e.g., "Engineer Report — example.com - DNS Tool").
- **Executive print minimum sizes**: Body 11pt, small text 9pt, badges 9pt, labels 8.5pt, metadata 9pt, code 8.5pt, footer 8.5pt. Text-muted color minimum #4b5563. Target audience: 40-50+ year old board members.
- **Executive button**: Uses custom `btn-outline-executive` class (muted gray #9ca3af text, #6b7280 border). NOT btn-outline-light (too bright) or btn-outline-warning (clashes with TLP:AMBER).
- **Font Awesome subset**: 110 glyphs in `static/webfonts/fa-solid-900.woff2`. Verify with fonttools before regenerating. CSS refs in `fontawesome-subset.min.css`.

## System Architecture

### Core System
The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client, DoH fallback, UDP fast-probe for subdomain discovery, three-layer CT+wildcard+DNS subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, SMTP transport verification, CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling, "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation, SMIMEA/OPENPGPKEY detection, `security.txt` detection, AI Surface Scanner (detects `llms.txt`, AI crawler governance, prefilled prompts, CSS-hidden prompt injection), SPF redirect chain handling with loop detection, DNS history timeline via SecurityTrails API, IP Investigation, OpenPhish integration, and Email Header Analyzer for comprehensive email security analysis.
- **Enterprise DNS Detection**: Automatic identification of major enterprise-grade DNS providers and blocklisting of legacy providers.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" for RFC compliance and observation-based language.
- **Remediation Engine**: Generates RFC-aligned "Priority Actions" (fixes) for various DNS records, categorized by severity with DNS record examples.
- **Mail Posture Labels**: Observation-based labels ("Strongly Protected", "Moderately Protected", etc.) aligned with NIST/CISA.
- **Cache Policy**: DNS client cache is disabled for live queries; limited caches are used only for external services.
- **Drift Engine Foundation**: Implements canonical posture hashing to detect configuration drift over time.
- **Licensing**: Uses BSL 1.1 (Business Source License) for both public and private repositories, with a rolling change date to Apache-2.0. The license permits internal use, own-domain audits, and MSP/consultant client audits, while prohibiting hosted/managed competitive offerings.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, full mobile responsiveness, and dual print reports (Engineer + Executive) with configurable TLP classification (default: TLP:AMBER, aligned with CISA Cyber Hygiene practice).
- **Dual Print Reports**: Engineer (full technical detail, `window.print()`) and Executive (condensed board-ready summary, `/analysis/:id/executive`). Both use same live analysis data. Executive template: `results_executive.html`. Engineer button: `btn-outline-info`. Executive button: `btn-outline-light` (changed from `btn-outline-warning` to avoid color conflict with TLP:AMBER dropdown).
- **TLP Policy**: Default TLP:AMBER for all reports (security posture data may reveal actionable vulnerabilities). Users can select TLP:GREEN (community sharing) or TLP:CLEAR (unlimited) via dropdown before printing. FIRST TLP v2.0 colors: AMBER=#ffc000, GREEN=#33a532, CLEAR=white/border.
- **Pages**: Index, Results, Results Executive, History, Statistics, Compare, Sources, IP Investigate, Email Header Analyzer, Changelog, Security Policy.

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