# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It serves as a **verification instrument** — when a sysadmin changes a DNS record and rescans, they must see the new state immediately. Every conclusion is independently verifiable using standard commands. Philosophy: **No proprietary magic.**

It audits critical DNS records such as SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, and CAA, with automatic subdomain discovery and DNS history timeline via SecurityTrails API integration. It includes an AI Surface Scanner for detecting AI-related governance signals, an IP Investigation workflow, and an Email Header Analyzer. All public-facing text uses observation-based language (not definitive claims) per the Analysis Integrity Standard.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application is implemented in Go using the Gin framework, providing high performance and concurrency. The architecture follows an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe query generation, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client (no cross-request cache — TTL=0 for live queries), DoH fallback, CT subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, SMTP transport verification (observation-based language), CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling (Observed/Inferred/Third-party), "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB record intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation detection, SMIMEA/OPENPGPKEY email encryption detection, **security.txt** detection, **AI Surface Scanner** (detects llms.txt at both `/.well-known/` and root paths, AI crawler governance, prefilled AI prompts, CSS-hidden prompt injection artifacts), **SPF redirect= chain handling** with loop detection, **DNS history timeline** via SecurityTrails API (24h cache, 50 calls/month limit), **IP Investigation** for IP-to-domain relationships, **OpenPhish** phishing URL feed integration, and **Email Header Analyzer** (paste/upload .eml files or raw headers for SPF/DKIM/DMARC verification, delivery route tracing, alignment checking, spoofing detection, base64/quoted-printable body decoding, phishing pattern scanning, Big Questions critical thinking prompts, spam flag detection, BCC delivery detection).
- **Enterprise DNS Detection**: Automatic identification of enterprise-grade DNS providers (Route 53, Cloudflare, NS1, Azure DNS, Google Cloud DNS, Akamai, UltraDNS, Oracle Dyn, CSC Global, GoDaddy, Namecheap, Hurricane Electric, DigitalOcean, Hetzner, Vultr, DNSimple, Netlify, Vercel). Legacy provider blocklist prevents false Enterprise tagging (Network Solutions, Bluehost, HostGator, etc.). Protected by golden rule tests that fail if maps are emptied or blocklist is removed.
- **SMTP Transport Status**: Live SMTP TLS validation with three display states: "All Servers" (live probe succeeded), "Inferred" (port 25 blocked but DNS signals confirm security — MTA-STS, TLS-RPT, provider inference), "No Mail" (no MX records). The "Inferred" status replaced a previous bug where DNS-inferred domains showed "No Mail".
- **SEO**: Comprehensive meta descriptions, Open Graph, and Twitter Card tags. All claims observation-based per Analysis Integrity Standard.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" ensuring results align with RFCs and industry best practices, enforced by automated golden rules tests. Observation-based language throughout (e.g., "Transport encryption observed?" not "Is email encrypted?").
- **Golden Rules Tests**: `golden_rules_test.go` guards critical behaviors: email spoofing verdicts, DMARC rua detection, enterprise provider detection (all providers + map non-empty checks), legacy provider blocklist enforcement, no overlap between enterprise and blocklist, and infrastructure tier classification.
- **Remediation Logic**: RFC-aligned best practices for SPF (~all vs -all, lookup count), DMARC reporting, DKIM key strength, DNSSEC broken chain, DANE without DNSSEC, and CAA. Posture summary categories include "Action Required", "Monitoring", "Configured", and "Not Configured".
- **Cache Policy**: DNS client cache disabled (TTL=0) — every scan does live queries. Only defensible caches retained: RDAP (24h, rate-limit protection), DNS History (24h, 50 calls/month), CT subdomains (1h, append-only data), RFC metadata (24h, reference data).

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare, Sources, IP Investigate, Email Header Analyzer.
- **Print/PDF Report**: Executive-grade print stylesheet with TLP:CLEAR classification, domain banner, colored sections, B&W laser-safe palette, and controlled page breaks.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella (for consensus).
- **IANA RDAP**: For registry data lookups (24h cache due to aggressive rate limits).
- **ip-api.com**: For visitor IP-to-country lookups.
- **crt.sh**: For Certificate Transparency logs (1h cache, append-only historical data).
- **SecurityTrails**: For DNS history timeline (user-provided API key, no server-side storage; 24h result cache). Users enter their own SecurityTrails API key on the results page — key is sent directly to SecurityTrails and never stored.
- **Team Cymru**: DNS-based IP-to-ASN attribution.
- **OpenPhish**: Community phishing URL feed for real-time phishing detection.

### Database
- **PostgreSQL**: The primary database for persistent storage. **Dev and production use separate databases** (Replit platform change, Dec 2025). The production database contains real user scan history; the dev database only has test scans. This is a platform-enforced separation — not configurable. Always verify features against the published site for real-world accuracy.

## Build & Deploy Checklist
Before publishing or after making changes to static assets or Go code, always verify:

1. **CSS minification** — `static/css/custom.min.css` must be regenerated from `custom.css` using `npx csso custom.css -o custom.min.css`. Check that min file is significantly smaller than source (not a copy).
2. **JS minification** — `static/js/main.min.js` must be regenerated from `main.js` using `npx terser main.js -o main.min.js --compress --mangle`. Verify with `node -c main.min.js` (no syntax errors).
3. **Version bump** — After changing any static asset (CSS/JS), bump `AppVersion` in `go-server/internal/config/config.go` so browsers fetch the new files instead of cached old ones. The version appears in `?v=` query strings on static URLs.
4. **Go binary rebuild** — After changing any `.go` file, rebuild: `cd go-server && GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/` then swap via `cd /home/runner/workspace && mv /tmp/dns-tool-new dns-tool-server-new && mv dns-tool-server-new dns-tool-server`.
5. **Binary cleanup** — Only keep `dns-tool-server`. Remove stale copies (`dns-tool`, `go-server/server`). All binary names are in `.gitignore`.
6. **Run golden rules tests** — `cd go-server && GIT_DIR=/dev/null go test -run TestGoldenRule ./internal/analyzer/ -v` to verify enterprise detection, legacy blocklist, and email verdicts.
7. **Restart workflow** — After binary swap, restart the "Start application" workflow.

## Public Repo Safety (Secret Sauce Protection)
The public GitHub repo (`DnsToolWeb`) must NEVER expose proprietary intelligence:
- **Never reveal** analyzer detection methods, scoring algorithms, provider database contents, schema keys, or remediation logic in public docs (DOCS.md, FEATURE_INVENTORY.md, README)
- **Never include** legacy Python source code (dns_analyzer.py, dns_providers.py, etc.) — these are gitignored under docs/legacy/
- **Public docs should be high-level** — what the tool does, not how it does it internally
- **Definition of Done** (`DOD.md`) governs every change — see checklist
- **Never request secrets** — only accept them when the user provides them for development
- **Never output secrets** in code, logs, docs, or error messages

## GitHub Repositories
- **`careyjames/DnsToolWeb`** (Public) — This Replit project. Set as `origin` remote. All web app code pushes here. Docs must be sanitized before pushing.
- **`careyjames/dnstool-intel`** (Private) — "Secret sauce" proprietary intelligence: analyzer logic, scoring, golden rules, remediation, AI surface scanner. Never push to public repos.
- **`careyjames/dns-tool`** (Public, Legacy) — Original CLI version. Archived/legacy. Do NOT push to this repo — it points users to the web app now.
- **`careyjames/it-help-tech-site`** (Public) — Main company site (www.it-help.tech). Rust/Zola static site on AWS. Separate project.
