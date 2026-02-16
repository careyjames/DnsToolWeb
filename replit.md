# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is an OSINT platform for comprehensive, RFC-compliant domain security analysis. It uses publicly available intelligence (DNS records, certificate transparency logs, RDAP data, web resources) to provide immediate, verifiable domain state information. Key capabilities include auditing critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Intelligence, and an Email Header Analyzer. The project aims for an open-source model while protecting commercial viability, targeting both technical sysadmins and non-technical executives.

## User Preferences
- Preferred communication style: Simple, everyday language.
- Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets both technical sysadmins and non-technical executives (board-level).
- Memory persistence is critical — `replit.md` is the single source of truth between sessions. Update it every session with decisions, changes, and rationale.
- **IMPORTANT**: If `replit.md` appears truncated or reset, restore from `EVOLUTION.md` which is the persistent backup. Always read BOTH files at session start.
- **CRITICAL**: Read the "Failures & Lessons Learned Timeline" section at the bottom of `EVOLUTION.md` before making any changes. It documents recurring mistakes (CSP inline handlers, font subset issues, PDF title format, print readability) with correct solutions.

## System Architecture

### Core System
The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client, DoH fallback, three-layer CT+wildcard+DNS subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, Mail Transport Security assessment, CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling, "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation, SMIMEA/OPENPGPKEY detection, `security.txt` detection, AI Surface Scanner (detects `llms.txt`, AI crawler governance, prefilled prompts, CSS-hidden prompt injection), SPF redirect chain handling with loop detection, DNS history timeline, IP Intelligence, OpenPhish integration, Email Header Analyzer, public exposure checks, expanded exposure checks (probing 8 well-known misconfiguration paths), and report integrity hash (SHA-256 tamper-evident fingerprint).
- **Password Manager Compatibility**: API key fields are designed for password manager save/fill support using consistent naming, `type="password"`, and proper `<label for>` attributes.
- **Enterprise DNS Detection**: Automatic identification of major enterprise-grade DNS providers and blocklisting of legacy providers.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" for RFC compliance and observation-based language.
- **Remediation Engine**: Generates RFC-aligned "Priority Actions" (fixes) for various DNS records, categorized by severity with DNS record examples.
- **Mail Posture Labels**: Observation-based labels ("Strongly Protected", "Moderately Protected", etc.) aligned with NIST/CISA.
- **Cache Policy**: DNS client cache is disabled for live queries; limited caches are used only for external services.
- **Drift Engine Foundation**: Implements canonical posture hashing to detect configuration drift over time.
- **Licensing**: Uses BSL 1.1 (Business Source License) for both public and private repositories, with a rolling change date to Apache-2.0, permitting internal use and client audits, while prohibiting competitive offerings.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, full mobile responsiveness, and dual intelligence products (Engineer's DNS Intelligence Report + Executive's DNS Intelligence Brief) with configurable TLP classification (default: TLP:AMBER, aligned with CISA Cyber Hygiene practice). Full FIRST TLP v2.0 hierarchy.
- **Dual Intelligence Products**: Engineer's DNS Intelligence Report (full technical detail) and Executive's DNS Intelligence Brief (condensed board-ready summary) are generated from the same live analysis data. Executive template: `results_executive.html`.
- **Homepage hero hierarchy**: Badge ("DNS Security Intelligence") → H1 ("Domain Security Audit") → Tagline ("We answer the BIG questions.") → Subtitle (references both intelligence products) → Protocol tags.
- **TLP Policy**: Default TLP:AMBER for all reports. TLP v2.0 hierarchy (RED → AMBER+STRICT → AMBER → GREEN → CLEAR) is supported. CSS specificity rules are critical for badge and button colors.
- **CSS cache-busting**: Requires `npx csso` for minification, bumping `AppVersion`, rebuilding the Go binary, and restarting the workflow.
- **Pages**: Index, Results, Results Executive, History, Statistics, Compare, Sources, IP Intelligence, Email Header Analyzer, Changelog, Security Policy, Brand Colors (hidden, noindex).
- **Brand Colors Page** (`/brand-colors`): Canonical color reference for design, documenting brand palette and standards-aligned cybersecurity colors (FIRST TLP v2.0, CVSS severity NVD implementation).
- **Protocol "Big Questions"**: Every section and protocol card features a plain-language question with a data-driven badge answer (e.g., SPF "Does this domain publish who can send email on its behalf?"). These Q&A pairs are slated for `FAQPage` JSON-LD schema markup for SEO.

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
- **PostgreSQL**: Primary database for persistent storage, with separate databases for development and production environments. Analysis data is immutable and append-only from v26.19.0 forward, ensuring auditable records.