# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform for comprehensive, RFC-compliant domain security analysis. Its primary purpose is to provide immediate and verifiable domain state information for sysadmins, adhering to a "No proprietary magic" philosophy where every conclusion is independently verifiable. It audits critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), offers automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Investigation, and an Email Header Analyzer. The project aims for an open-source model while protecting commercial viability and targets both technical and non-technical users.

## User Preferences
- Preferred communication style: Simple, everyday language.
- Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets both technical sysadmins and non-technical executives (board-level).
- Memory persistence is critical — `replit.md` is the single source of truth between sessions. Update it every session with decisions, changes, and rationale.
- **IMPORTANT**: If `replit.md` appears truncated or reset, restore from `EVOLUTION.md` which is the persistent backup. Always read BOTH files at session start.

## Recent Changes (Session Log)

### February 14, 2026 — License Migration + Stub Defaults Fix + License Hardening

**License Migration (AGPL → BSL 1.1)**:
- All 111 Go source files updated from AGPL-3.0 to BUSL-1.1 headers
- LICENSE file replaced with BSL 1.1 text
- Created LICENSING.md explaining open-core model
- Rationale: AGPL created legal tension with proprietary private companion repo and hindered acquisition/commercial potential
- Both public (DnsToolWeb) and private (dnstool-intel) repos now BSL 1.1

**License Hardening (Additional Use Grant rewrite)**:
- Rewrote Additional Use Grant modeled on HashiCorp's BSL structure
- Rolling Change Date: 3 years from publication of each version (pre-2026-02-14 versions: 2029-02-14)
- MSP/Consultant carve-out: Explicitly permits professional services for client domain audits
- Explicit "Competitive Offering" definition: hosted/managed/API + material DNS audit functionality
- Clear permitted uses: internal operations, own-domain audits, professional services, non-production

**Stub Defaults Bug Fix (Critical)**:
- `isHostedEmailProvider()` stub: `false` → `true` (assume hosted, suppress DANE recs)
- `isBIMICapableProvider()` stub: `true` → `false` (no false BIMI capability claims)
- Philosophy: conservative defaults prevent incorrect recommendations

**BIMI Recommendation Logic Correction**:
- Removed provider-based gating from `appendBIMIFixes` (BIMI is receiver-side)
- Now recommends BIMI for any domain with DMARC reject, regardless of provider

**New Golden Rule Tests** (25 total, 23 previous + 2 new):
- `TestGoldenRuleHostedProviderNoDANE`
- `TestGoldenRuleBIMIRecommendedRegardlessOfProvider`

## System Architecture

### Core System
The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client (TTL=0 for live queries), DoH fallback, CT subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, SMTP transport verification, CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling, "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation, SMIMEA/OPENPGPKEY detection, `security.txt` detection, AI Surface Scanner (detects `llms.txt`, AI crawler governance, prefilled prompts, CSS-hidden prompt injection), SPF redirect chain handling with loop detection, DNS history timeline via SecurityTrails API, IP Investigation, OpenPhish integration, and Email Header Analyzer for comprehensive email security analysis.
- **Enterprise DNS Detection**: Automatic identification of major enterprise-grade DNS providers and blocklisting of legacy providers to prevent false positives.
- **SMTP Transport Status**: Live SMTP TLS validation with "All Servers", "Inferred", and "No Mail" states, providing accurate mail posture even when direct probes are blocked.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" for RFC compliance and observation-based language.
- **Golden Rules Tests**: `golden_rules_test.go` guards critical behaviors, including email spoofing verdicts, DMARC RUA detection, enterprise provider identification, remediation engine functionality, mail posture labeling, and stub registry completeness.
- **Remediation Engine**: Generates RFC-aligned "Priority Actions" (fixes) for various DNS records, categorized by severity with DNS record examples.
- **Mail Posture Labels**: Observation-based labels ("Strongly Protected", "Moderately Protected", etc.) aligned with NIST/CISA.
- **Cache Policy**: DNS client cache is disabled for live queries; limited caches are used only for external services like RDAP, DNS History, CT subdomains, and RFC metadata.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare, Sources, IP Investigate, Email Header Analyzer.
- **Print/PDF Report**: Executive-grade print stylesheet with TLP:CLEAR classification and professional presentation.

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

## Quality Golden Standards
- **Mozilla Observatory**: 130+ (target 135). CSP uses `default-src 'none'` with nonce-based `style-src`.
- **Lighthouse**: Performance 98%+, Accessibility 100%, Best Practices 100%, SEO 100%.
- **Golden Rules Tests**: All must pass — `cd go-server && GIT_DIR=/dev/null go test -run TestGoldenRule ./internal/analyzer/ -v`
- **Stub Registry**: 13 known stubs. New stubs MUST be registered in `TestGoldenRuleStubRegistryComplete`.
- **Private Repo Sync**: Track via `dnstool-intel-staging/STUB_AUDIT.md`. Boundary functions: `isHostedEmailProvider`, `isBIMICapableProvider`, `isKnownDKIMProvider`.

## Build & Deploy Checklist
1. CSS minification (`npx csso`), JS minification (`npx terser`), version bump (`AppVersion` in config.go)
2. Go binary rebuild: `cd go-server && GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/`
3. Binary swap: `mv /tmp/dns-tool-new dns-tool-server-new && mv dns-tool-server-new dns-tool-server`
4. Run golden rules tests, restart workflow

## Licensing
- **Public repo (`DnsToolWeb`)**: BSL 1.1 — rolling Change Date (3 years per version), converts to Apache-2.0. Additional Use Grant permits internal use, own-domain audits, MSP/consultant client audits. Prohibits hosted/managed competitive offerings.
- **Private repo (`dnstool-intel`)**: BSL 1.1 (same terms).
- **Legacy CLI repo (`dns-tool`)**: MIT — archived.
- **Open-core model**: Public shell + private intelligence. Both BSL 1.1.

## Public Repo Safety
Never expose analyzer detection methods, scoring algorithms, provider databases, schema keys, or remediation logic in public docs. See `DOD.md` for full checklist.

## GitHub Repositories
- **`careyjames/DnsToolWeb`** (Public) — This Replit project. `origin` remote.
- **`careyjames/dnstool-intel`** (Private) — Secret sauce. Agent has push access via GitHub API.
- **`careyjames/dns-tool`** (Public, Legacy) — Archived CLI. Do NOT push here.
- **`careyjames/it-help-tech-site`** (Public) — Company site. Separate project.
