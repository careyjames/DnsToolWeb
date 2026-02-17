# DNS Tool — Evolution Log (Breadcrumbs)

This file is the project's permanent breadcrumb trail — every session's decisions, changes, lessons learned, and rationale. It serves as a backup for `replit.md` (which may be reset by the platform) and as the canonical history of the project's evolution. If anything goes wrong, this is where you trace back what happened and why.

**Rules for the AI agent**:
1. At the start of every session, read this file AND `replit.md`.
2. At the end of every session, append new entries here with dates.
3. If `replit.md` has been reset/truncated, restore its content from this file.
4. **MANDATORY**: After ANY Go code changes, run `go test ./go-server/... -count=1` before finishing. This runs the boundary integrity tests that prevent intelligence leaks, duplicate symbols, stub contract breakage, and architecture violations.

---

## Session: February 14, 2026

### License Migration (AGPL → BSL 1.1)
- **Decision**: Migrate all source files from AGPL-3.0 to BSL 1.1 (Business Source License)
- **Rationale**: AGPL created legal tension with the proprietary private companion repo (`dnstool-intel`) and hindered acquisition/commercial potential. User quote: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- **Scope**: All 111 Go source files updated with BUSL-1.1 headers. LICENSE file replaced. LICENSING.md created.
- **Both repos** (public `DnsToolWeb` and private `dnstool-intel`) now BSL 1.1.
- **Change License**: Apache-2.0 (what it converts to after the Change Date)

### License Hardening (Additional Use Grant)
- **Decision**: Rewrite the Additional Use Grant modeled on HashiCorp's BSL structure
- **Rolling Change Date**: 3 years from publication of each version (not a fixed calendar date). Pre-2026-02-14 versions: Change Date is 2029-02-14. HashiCorp uses 4 years; we chose 3 for faster open-source conversion.
- **MSP/Consultant carve-out**: Explicitly permits security consultants, MSPs, and IT administrators to use the tool for client domain audits. Only prohibits offering the tool itself as a standalone hosted/managed product.
- **"Competitive Offering" definition**: Must be BOTH (a) offered to third parties on a hosted/managed/embedded/API basis AND (b) providing DNS security audit functionality that is material to the offering's value.
- **Permitted uses**: Internal operations, own-domain audits, professional services for clients, non-production (dev/test/research/education)
- **Why this matters**: Plain BSL only grants non-production use by default. Without the explicit Additional Use Grant, even sysadmins auditing their own domains would technically violate the license.

### Stub Defaults Bug Fix (Critical)
- **`isHostedEmailProvider()`**: Changed from returning `false` to `true`
  - Old: Assumed all providers support DANE → recommended DANE/TLSA for Google Workspace (impossible to deploy)
  - New: Safely assumes hosted email → suppresses DANE recommendations unless private repo intelligence confirms otherwise
- **`isBIMICapableProvider()`**: Changed from returning `true` to `false`
  - Old: Claimed BIMI capability for unknown providers
  - New: Conservative default prevents false claims
- **Design principle**: When a stub controls recommendations, the default must produce the LEAST incorrect advice. Wrong recommendations erode user trust.

### BIMI Recommendation Logic Correction
- **Decision**: Remove provider-based gating from `appendBIMIFixes` in remediation.go
- **Rationale**: BIMI is receiver-side verification (Gmail, Apple Mail decide whether to show the logo). The sending provider is irrelevant. Now recommends BIMI for any domain with DMARC reject policy, regardless of provider.

### New Golden Rule Tests (25 total)
- `TestGoldenRuleHostedProviderNoDANE` — ensures hosted email providers never get DANE recommendations
- `TestGoldenRuleBIMIRecommendedRegardlessOfProvider` — ensures BIMI recommendations aren't gated by provider
- Previous 23 tests unchanged; all 25 pass.

### Key Boundary Functions (Public Stub ↔ Private Intelligence)
| Function | Stub Default | Private Repo |
|----------|-------------|-------------|
| `isHostedEmailProvider(domain, mxHosts)` | `true` | Checks provider databases |
| `isBIMICapableProvider(domain, mxHosts)` | `false` | Checks VMC-capable providers |
| `isKnownDKIMProvider(domain, mxHosts)` | `false` | Checks DKIM provider database |

### Documentation Structure
Files and their purposes:
| File | Purpose | Public? |
|------|---------|---------|
| `replit.md` | Agent memory / project context (may be reset by platform) | No (Replit only) |
| `EVOLUTION.md` | Persistent decision log (this file — backup for replit.md) | Yes (public repo) |
| `DOCS.md` | Technical documentation for the app | Yes |
| `DOD.md` | Definition of Done checklist | Yes |
| `LICENSING.md` | Plain-language license explanation | Yes |
| `LICENSE` | Legal license text (BSL 1.1) | Yes |
| `docs/FEATURE_INVENTORY.md` | High-level feature list | Yes |
| `dnstool-intel-staging/STUB_AUDIT.md` | Stub-to-private-repo mapping | No (gitignored) |

### Risks Called Out by Legal Analysis
- "Competitive" definitions can backfire if too broad (scares users) or too narrow (competitors route around)
- Prior AGPL contributions need permission or rewrites for relicensing (no external contributors exist for this project)
- Trademarks are separate from code licensing — BSL does not grant trademark rights
- Data provenance in private repo is an acquisition due-diligence concern
- Go ecosystem: pkg.go.dev won't recognize BSL as OSI-approved (acceptable since this is an app, not a library)

---

## Documentation Accuracy Status (as of Feb 14, 2026)

All documentation files verified accurate:
- `LICENSE` — Updated with rolling Change Date, MSP carve-out, explicit definitions
- `LICENSING.md` — Reflects LICENSE terms in plain language
- `DOCS.md` — Technical docs accurate, no proprietary intelligence exposed
- `DOD.md` — Definition of Done checklist accurate
- `docs/FEATURE_INVENTORY.md` — Feature list accurate
- `dnstool-intel-staging/STUB_AUDIT.md` — Stub defaults corrected (isHostedEmailProvider→true, isBIMICapableProvider→false)
- Private repo: LICENSE and LICENSING.md pushed and in sync with public repo

### Session continuation: February 14, 2026 — License Definition Hardening + Commercial Features

**License Definition Hardening**:
- Added formal definitions for "Hosted", "Managed", and "Embedded" to LICENSE
- Modeled on HashiCorp's BSL approach for legal precision
- "Hosted": service operator controls infrastructure, makes functionality available to third parties
- "Managed": operator handles deployment/maintenance/upgrades on behalf of end user
- "Embedded": including Licensed Work in source/executable/packaged form, or requiring it for product operation
- LICENSING.md updated with matching plain-language definitions

**Commercial Features Section**:
- Added "Commercial Licensing" section to LICENSING.md
- Lists features available under commercial license: Full Platform, Enterprise Intelligence, Deployment Options, Support
- Includes "Who Should Contact Us" guidance for potential buyers
- Contact: licensing@it-help.tech

**Repo Sync**:
- Both LICENSE and LICENSING.md pushed to private repo (dnstool-intel) and verified byte-identical

### Session continuation: February 14, 2026 — Subdomain Discovery Enhancement

**Root Cause**: Domains using wildcard TLS certificates (like it-help.tech with `*.it-help.tech`) showed "0 subdomains" because CT logs only had wildcard entries which got normalized to the base domain and filtered out. The subdomain discovery relied solely on CT logs.

**Fix — Three-Layer Free Discovery** (no paid API dependencies):
1. **CT log scanning**: Parses crt.sh Certificate Transparency entries for explicit subdomain names
2. **Wildcard cert detection**: Detects `*.domain` patterns in CT entries, reports active/expired status with info banner
3. **DNS probing**: Probes ~90 common subdomain names (www, mail, api, admin, etc.) via concurrent DNS lookups with 10-goroutine semaphore cap
4. **Rich output**: Produces all fields the template expects (name, source, is_current, cert_count, first_seen, issuers, cname_target, wildcard_certs)

**SecurityTrails NOT used in automatic discovery** (reverted same session):
- SecurityTrails `FetchSubdomains()` was briefly wired into the pipeline but immediately reverted
- Reason: The server-side SecurityTrails API key has a hard 50-request/month limit. Using it automatically on every scan would exhaust the budget within hours. Once exhausted, the key is dead for the rest of the month — no DNS history, no IP Intelligence, nothing.
- Correct pattern: SecurityTrails is user-key-only. Users provide their own API key on DNS History and IP Intelligence pages. The server key is reserved for features where users explicitly opt in.
- **Rule**: Never call SecurityTrails automatically in the analysis pipeline. It's a user-provided-key feature only.

**Source attribution**: "Certificate Transparency + DNS Intelligence". Caveat lists CT logs, DNS probing, and CNAME traversal.

**Date parsing robustness**: Added `parseCertDate()` that handles multiple formats (ISO 8601, date-only, datetime) to prevent silent failures from unexpected crt.sh response formats.

**New Golden Rule Tests** (27 total, 25 previous + 2 new):
- `TestGoldenRuleWildcardCTDetection` — wildcard-only CT entries produce 0 explicit subdomains but trigger wildcard flag
- `TestGoldenRuleWildcardNotFalsePositive` — explicit subdomain entries don't falsely trigger wildcard detection

**Result**: Subdomain discovery uses three free intelligence layers (CT + wildcard + DNS probing). No paid API calls. it-help.tech now shows www.it-help.tech via DNS probing with CNAME to CloudFront.

### Session continuation: February 14, 2026 — Subdomain Discovery Performance Optimization

**Root Cause**: The DNS probing layer (~140 common subdomain names) was timing out because:
1. Each probe used DoH (DNS-over-HTTPS to dns.google) — full TLS/HTTPS connection per query
2. Only 10 concurrent goroutines meant 14+ batches of serial HTTPS calls
3. The shared 60-second analysis context was being consumed before all probes completed
4. Result: `ct_subdomains` task hit 60+ seconds (timeout), only 2 of 5 known subdomains found

**Fix — High-Speed UDP DNS Probing**:
1. **New `ProbeExists()` method** in DNS client: Uses lightweight UDP queries (single packet) to 8.8.8.8 with fallback to 1.1.1.1, instead of expensive DoH HTTPS connections
2. **Independent context**: `probeCommonSubdomains` gets its own 30-second context, independent of the shared analysis context
3. **Higher concurrency**: Bumped from 10 to 20 goroutines for both probing and enrichment
4. **Single query per name**: Only queries A record and extracts CNAME from the response (instead of 3 separate A/AAAA/CNAME queries)
5. **Enrichment also independent**: `enrichSubdomainsV2` gets its own 30-second context with 20-goroutine concurrency

**Performance Result**:
- **Before**: 60+ seconds (timeout), incomplete results, only 2/5 subdomains
- **After**: 1.2 seconds, all 5 known it-help.tech subdomains found (dnstool, schedule, screen, server, www) plus 4 DNS-related names (dmarc, sts, tls, u)

**Design Lesson**: DoH is orders of magnitude more expensive than UDP DNS for bulk operations. A single UDP DNS query is one packet sent and one received (~100 bytes each). A single DoH query requires TCP handshake + TLS handshake + HTTP/2 framing + HTTPS overhead — hundreds of packets. For bulk probing 140+ names, the difference is catastrophic.

**Golden Rule Tests**: 27 total, all pass. No new golden rule tests added (performance optimization, not behavior change).

---

## Session: February 15, 2026 — Performance Hardening + PWA Best Practices

### Performance Hardening (Total Analysis: 60s → ~27s)

**Problem**: While ct_subdomains probing was fixed with UDP, three critical bottlenecks remained:
1. crt.sh CT query inherited the parent 60-second context — if crt.sh was slow (common), it consumed the entire timeout
2. Subdomain enrichment (`enrichSubdomainsV2`) still used DoH (`QueryDNS`) instead of UDP (`ProbeExists`)
3. ASN lookup (Team Cymru) ran sequentially in the post-parallel phase, each DoH query timing out against the parent 60s context

**Fixes Applied**:
1. **crt.sh CT query**: Independent 10-second context via `context.Background()` — crt.sh can no longer block the analysis
2. **Subdomain enrichment**: Switched from `QueryDNS` (DoH-first → UDP fallback, two queries per subdomain) to `ProbeExists` (single UDP query with CNAME extraction) — matches the probing method
3. **ASN lookup**: Independent 8-second context — Team Cymru queries capped at 8s instead of consuming remaining parent context
4. **Probing timeout**: Tightened from 30s to 15s (UDP queries are fast, 3s timeout per query)
5. **Enrichment timeout**: Tightened from 30s to 10s

**Result**: Total analysis time dropped from 60s to ~27s.

### PWA Best Practices

**Maskable Icons**: Created 192x192 and 512x512 maskable variants with proper safe-zone padding (inner 80%).

**Manifest Improvements**: Added `id`, `scope`, and maskable icon entries.

**Files changed**: `static/manifest.json`, `static/icons/icon-maskable-*.png`, `go-server/internal/analyzer/subdomains.go`, `go-server/internal/analyzer/asn_lookup.go`

### Changelog Date Audit (Full Correction)

**Problem**: Multiple changelog entries had incorrect dates. The version numbering scheme (26.14.x, 26.13.x, 26.12.x) was misinterpreted as encoding dates (Feb 14, Feb 13, Feb 12). In reality, version numbers are feature-level counters with no date significance.

**Corrected dates** (verified by user on Feb 15, 2026):

| Entry | Old Date | Correct Date | Reason |
|-------|----------|--------------|--------|
| High-Speed Subdomain Discovery | Feb 14 | Feb 14 | Actually shipped Feb 14 |
| Intelligence Sources Inventory | Feb 14 | Feb 12 | Shipped days before Feb 14 |
| PTR-Based Hosting Detection | Feb 14 | Feb 12 | Shipped days before Feb 14 |
| IP-to-ASN Attribution | Feb 14 | Feb 12 | Shipped days before Feb 14 |
| Incident Disclosure | Feb 14 | Feb 11 | Incident occurred Feb 10-11 |
| Honest Data Reporting | Feb 14 | Feb 11 | Response to incident |
| DNS History Cache | Feb 14 | Feb 13 | Shipped Feb 13 |
| Email Header Analyzer | Feb 14→Feb 12 | Feb 12 | Fixed in prior session |
| Enterprise DNS Detection | Feb 14→Feb 12 | Feb 12 | Fixed in prior session |

**Prevention**: Added `CHANGELOG DATE POLICY` comment block at top of `changelog.go` with:
- Explicit rule: version numbers ≠ dates
- Canonical date mapping for every entry
- Instruction to use named date constants, never inline strings

**New golden rule test**: `TestGoldenRuleSubdomainDiscoveryUnder60s` — integration test runs live subdomain discovery against it-help.tech, asserts <60s completion and finds required subdomains (dnstool, www). 28 golden rule tests total, all pass.

**Version**: 26.15.24

### OpenPhish Attribution + Email Header Promotion (Feb 15, 2026)

**OpenPhish Threat Intelligence Attribution**:
- Added OpenPhish Community Feed to Sources page (`sources.go`, `sources.html`) with new "Threat Intelligence" category
- `getThreatSources()` function returns OpenPhish entry with Community badge, Free badge, verify command, and documentation link
- Attribution added to Email Header Analyzer: trust bar on form page, body analysis section on results page
- Verify command shortened to `openphish.com/feed.txt` to prevent card layout overflow

**Email Header Analyzer Homepage Promotion**:
- Promotional banner added to homepage (`index.html`) below IP Intelligence card
- Matching card style with warning/gold color scheme: "Did this email actually come from who it claims?"
- Links to `/email-header` with BETA badge

**Files changed**: `go-server/internal/handlers/sources.go`, `go-server/templates/sources.html`, `go-server/templates/email_header.html`, `go-server/templates/index.html`, `go-server/internal/handlers/changelog.go`, `go-server/internal/config/config.go`

**Golden Rule Tests**: All 50 sub-tests pass, zero regressions
**Version**: 26.15.25

### Drift Engine Foundation — Phase 1 (Feb 15, 2026)

**Decision**: Begin building drift detection infrastructure — the highest-leverage feature for transitioning from episodic analysis to longitudinal monitoring. External analysis confirmed this as the critical inflection point for product maturity.

**Architecture Principle**: Live results are sacred. Snapshots are a side-effect of the save path, never served as live results, never cached.

**Canonical Posture Hashing** (`posture_hash.go`):
- `CanonicalPostureHash(results map[string]any) string` — deterministic SHA-256 fingerprint of security-relevant posture
- Posture vector covers: SPF (status, records), DMARC (status, policy, records), DKIM (status, selectors), MTA-STS (status, mode), TLS-RPT, BIMI, DANE (status, has_dane), CAA (status, tags), DNSSEC, mail posture label, MX hosts, NS servers
- Excludes volatile/cosmetic fields: TTL, analysis duration, country, CT subdomains, ASN, timestamps
- Order-independent: all lists sorted before hashing (MX, NS, selectors, CAA tags) to prevent false drift from DNS provider record reordering
- 10 new golden rule sub-tests (deterministic, drift detection, order independence, empty input)

**Database Extension**:
- `posture_hash VARCHAR(64)` column added to `domain_analyses` via ALTER TABLE
- Schema.sql updated, sqlc regenerated
- New query: `GetPreviousPostureHash(domain)` — returns most recent hash for future drift comparison

**Save Path Integration**:
- `analysis.go` `saveAnalysis()` computes hash and stores it — one-line addition, zero changes to analysis/rendering path
- All future analyses automatically fingerprinted

**Planning Doc**: `DRIFT_ENGINE.md` created with 4-phase roadmap (Foundation → Drift Detection → Timeline UI → Alerting)

**Golden Rule Tests**: All 60 sub-tests pass (50 original + 10 new posture hash), zero regressions
**Files**: `posture_hash.go`, `posture_hash_test.go` (new), `schema.sql`, `domain_analyses.sql`, `dbq/*` (regenerated), `analysis.go`, `DRIFT_ENGINE.md` (new)

### Dual Intelligence Products: Engineer's DNS Intelligence Report & Executive's DNS Intelligence Brief (Feb 15, 2026)

**Decision**: Implement dual intelligence product system — Engineer's DNS Intelligence Report (comprehensive technical detail) and Executive's DNS Intelligence Brief (concise board-ready summary). Live results are sacred; both views use the same analysis data with different templates. Naming follows IC conventions: "Report" = comprehensive (like NIE), "Brief" = concise (like PDB/SEIB). Possessive form = "prepared for you."

**Executive's DNS Intelligence Brief** (`results_executive.html`):
- New handler `ViewAnalysisExecutive` and route `/analysis/:id/executive`
- 3-section structure: Executive Summary, Technical Findings, Appendix
- Executive Scorecard with 4 at-a-glance security status badges (Email Spoofing, Brand Impersonation, DNS Tampering, Certificate Control)
- AI Surface Scanner remains in Technical Findings section (not appendix) — it's a differentiator
- Posture hash never displayed in executive view
- TLP:CLEAR classification header for both print views
- Own `@media print` block with executive-specific styling

**Template Variable Scoping Fix**:
- Go `html/template` has strict block scoping — variables defined inside `{{if}}` blocks are inaccessible outside
- `$spfStatus`, `$dmarcStatus`, `$dmarcPolicy`, `$dnssecStatus` moved to top level (before first use) so they're available in both the scorecard section and the technical findings section
- Root cause: these variables were initially defined inside `{{if $posture}}` but used in the unconditional Technical Findings section

**Engineer Button Visibility Fix**:
- Engineer print button changed from `btn-outline-secondary` (dark gray, nearly invisible on dark theme) to `btn-outline-info` (light blue, clearly visible)
- Both buttons now clearly visible: Engineer (blue, printer icon) and Executive (amber, document icon)

**Golden Rule Tests**: All 60 sub-tests pass, zero regressions
**Version**: 26.15.26

---

## Session: February 15, 2026

### Font Awesome Subset — Root Cause & Prevention

**Root Cause**: Icons kept disappearing because the project uses a WOFF2 font SUBSET (not the full 300KB+ Font Awesome file). When templates add new `fa-*` classes, the glyph must exist in BOTH:
1. `static/css/fontawesome-subset.min.css` — CSS `:before` rule mapping class name to Unicode codepoint
2. `static/webfonts/fa-solid-900.woff2` — actual glyph outline in the font binary

If either is missing, the icon renders as an invisible blank space with no console error.

**Prevention Script**: `python3 go-server/scripts/audit_icons.py`
- Scans all Go templates for `fa-*` usage (found 118 icons)
- Cross-references against CSS rules (149 rules) and font glyphs (110 glyphs)
- Exit code 1 if any icon is missing from CSS or font
- Run before every release to catch missing icons early

**Regenerated Font**: Full FA 6.5.1 subset with all 110 needed glyphs (11KB compressed WOFF2). Added 56 missing CSS `:before` rules.

### Cookie Security Hardening

All application cookies now set via `http.SetCookie()` with:
- `Secure: true` (HTTPS-only)
- `HttpOnly: true` (no JavaScript access)
- `SameSite: StrictMode` (CSRF protection)

Locations: `ratelimit.go` (flash_message, flash_category), `csrf.go` (csrf_token).
Gin's `c.SetCookie()` replaced everywhere — it doesn't support SameSite.

### Favicon Reliability

- HTML `<link rel="icon">` uses `data:` URI (zero HTTP requests, no 404 possible)
- Navbar brand uses inline SVG shield (no font dependency)
- Both survive CDN outages, missing static files, and font subset issues

### SPF Provider Detection — MX Corroboration

**Problem**: `include:_spf.google.com` in SPF was being interpreted as "Google Workspace is the email provider" — even when MX records pointed elsewhere (e.g., Exchange, self-hosted mail). Many organizations add Google SPF for Calendar invitations, not email hosting.

**Fix**: SPF-based mailbox provider detection now requires MX corroboration:
- If SPF includes Google but MX points to a different provider → "SPF authorizes Google servers, but MX records point to [actual provider]. The Google SPF include likely supports ancillary services (e.g., calendar invitations)."
- If SPF includes Google but MX is self-hosted → Same ancillary explanation, provider detected as self-hosted
- If SPF includes Google AND MX confirms Google (aspmx.l.google.com) → "Google Workspace" label retained
- Security gateways (Proofpoint, Mimecast, etc.) still pass through correctly to the underlying provider

**Affected code**: `dkim.go` — renamed `detectSPFProvider` → `detectSPFMailboxProvider` / `detectSPFAncillaryProvider`, added MX corroboration logic in `detectPrimaryMailProvider`, added `spf_ancillary_note` to DKIM output map. Template `results.html` shows the ancillary note in an info alert.

### Icon Critical CSS Fix

**Problem**: Critical inline CSS set `width:1em;height:1em` on `.fas` elements without declaring `font-family`, preventing Font Awesome glyph rendering.

**Fix**: Replaced with proper FA-compatible critical CSS: `font-family:"Font Awesome 6 Free";font-weight:900;line-height:1` — icons now render immediately without waiting for the external CSS to load.

**Version**: 26.15.28

### TLP Policy — AMBER Default (CISA-Aligned)

**Date**: 2026-02-15

**Problem**: Reports were marked TLP:CLEAR ("Unlimited distribution"), which is inappropriate for security posture reports that may reveal actionable vulnerabilities. CISA's own Cyber Hygiene reports (WAS, CyHy) use TLP:AMBER.

**Decision**: Default TLP changed from CLEAR to AMBER for both Engineer and Executive print reports. Added a TLP selector dropdown (AMBER/GREEN/CLEAR) so users can adjust distribution scope before printing.

**Rationale** (aligned with FIRST TLP v2.0 and CISA practice):
- **TLP:AMBER** (default): Recipients may share within their organization and with clients who need to protect themselves. Appropriate for security posture reports that could expose weaknesses.
- **TLP:GREEN**: Recipients may share within their community (peers, industry groups) but not publicly. For inter-organization sharing.
- **TLP:CLEAR**: No restrictions. Only appropriate when the domain owner has explicitly authorized public distribution.

**Implementation**:
- Print header badge: amber-colored (#ffc000) with black text by default
- Footer disclaimer: CISA-style language about distribution scope
- JavaScript TLP selector: updates badge color, badge text, note text, and footer disclaimer
- CSS classes: `.tlp-amber`, `.tlp-green`, `.tlp-clear` with FIRST-standard colors
- Both Engineer (`results.html`) and Executive (`results_executive.html`) templates updated

**Key reference**: CISA WAS report for IT Help San Diego Inc. (2026-01-20) — uses TLP:AMBER on every page, password-protected PDF, controlled recipient list.

### SPF Ancillary Senders — Best Practical RT

Added `hostedrt.com` → "Best Practical RT" to `spfAncillarySenders` map. IETF.org uses `include:spf.hostedrt.com` for their Request Tracker ticketing system — similar to Zendesk/Freshdesk pattern already tracked.

**Version**: 26.15.29

---

## Failures & Lessons Learned — Detailed Analysis

This section provides detailed analysis of recurring issues, failed approaches, and root causes. **Always read this before starting work.** For a quick-reference table, see "Failures & Lessons Learned — Quick Reference" at the end of this document.

### CSP Inline Handler Failures (Recurring — v26.14 through v26.16)

**Problem**: Content Security Policy `script-src 'self' 'nonce-...'` blocks ALL inline event handlers (`onclick`, `onchange`, `onsubmit`). Every session that adds or modifies buttons must use `addEventListener` in a `<script nonce="{{.CspNonce}}">` block instead.

**Failed approaches**:
- Adding `onclick="window.print()"` to buttons — blocked by CSP
- Adding `onclick="loadDNSHistory()"` — blocked by CSP
- Any inline `on*` attribute — always blocked

**Correct pattern**: Use `id="myButton"` + `document.getElementById('myButton').addEventListener('click', fn)` inside a nonce'd script block.

**Files affected**: `results.html`, `results_executive.html`

### Font Awesome Subset — Missing Glyph False Alarm (v26.15–v26.16)

**Problem**: Icons like `fa-print` appeared to not render. Investigation showed the glyph IS in the woff2 subset (confirmed via fonttools). The real issue was **browser caching** of older versions.

**Lesson**: Always check the woff2 font file with `fonttools` before regenerating subsets. Force-refresh or version-bump the CSS query string to bust browser caches (`?v=XX.YY.ZZ`).

**Files**: `static/webfonts/fa-solid-900.woff2` (110 glyphs), `static/css/fontawesome-subset.min.css`

### PDF Title / Filename (v26.16)

**Problem**: Browser uses `<title>` as the PDF filename when printing to PDF. Engineer report had `<title>{{.Domain}} - DNS Tool</title>` → saved as "DNS Tool - Replit.pdf" which is wrong.

**Fix**: Changed to `<title>Engineer's DNS Intelligence Report — {{.Domain}} - DNS Tool</title>` and `<title>Executive's DNS Intelligence Brief — {{.Domain}} - DNS Tool</title>`.

**Lesson**: Always format `<title>` as "Report Type — domain - DNS Tool" for consistent PDF naming.

### Intelligence Document Naming Convention (v26.16.11)

**Decision**: Adopted IC (Intelligence Community) document naming conventions for the two report types.

**Naming hierarchy** (grounded in real IC conventions):
- **Engineer's DNS Intelligence Report** — Comprehensive technical document. "Report" = detailed, all-source analysis (like a National Intelligence Estimate). For the person who has to fix things.
- **Executive's DNS Intelligence Brief** — Concise decision-maker version. "Brief" = short, actionable, executive-level (like the Presidential Daily Brief / Senior Executive Intelligence Brief). For board members and leadership.

**Why possessive form**: "Engineer's" / "Executive's" signals "this was prepared for you" — personal ownership of the deliverable.

**Why "DNS Intelligence" not "Security"**: The tool is DNS Tool. The outputs are DNS intelligence products. "Security Intelligence" is literally MI5's name (UK Security Intelligence Service) — avoid unintentional identity borrowing.

**Locations where names appear** (must stay in sync):
1. `<title>` tag (becomes PDF filename): `Engineer's DNS Intelligence Report — {{.Domain}} - DNS Tool`
2. Print header (`.print-report-title`): `Engineer's DNS Intelligence Report`
3. Screen header (`<h1>`): `Engineer's DNS Intelligence Report`
4. OG/Twitter meta tags: Match `<title>`
5. Same pattern for Executive with "Brief" instead of "Report"

**Homepage hero hierarchy** (audit-produces-intelligence narrative):
1. Badge: "DNS Security Intelligence" (brand/discipline label)
2. H1: "Domain Security Audit" (SEO anchor — what the tool DOES)
3. Tagline: "We answer the BIG questions."
4. Subtitle: References both Engineer's DNS Intelligence Reports and Executive's DNS Intelligence Briefs (what the tool PRODUCES)
5. Protocol tags: SPF · DKIM · DMARC · etc. (what it checks)

**Rule**: The audit is the process. The intelligence products are the output. Never conflate the two. The homepage sells the audit; the results pages deliver the intelligence.

**Version**: 26.16.11

### Executive Print Readability (Recurring — v26.15 through v26.16)

**Problem**: Executive PDF print output has very small text. "Fine print" items (metadata, TLP notes, footer, finding labels, code blocks) are hard to read, especially for board-level executives.

**Root cause**: Print CSS used very small font sizes (6pt–7.5pt for metadata, 8pt for small text, 9.5pt body). Colors were too light for print (e.g., `#9ca3af` for text-muted).

**Fix applied in v26.16.1**:
- Body: 9.5pt → 10.5pt
- Small/fine print: 8pt → 9pt
- Badge text: 8pt → 9pt
- Finding labels: 9pt → 10pt
- Big Questions labels: 9.5pt → 10.5pt
- Section titles: 12pt → 13pt
- Footer text: 7.5pt → 8.5pt
- TLP badge: 7.5pt → 8.5pt
- Text-muted: #6b7280 → #4b5563 (darker for print)
- Footer disclaimer: #9ca3af → #6b7280 (darker)
- Card header icons: #94d1e8 → #b8e6f5 (brighter against gradient)

**Lesson**: Executive PDF print sizes should target minimum 8pt for ANY text element, 9pt+ for content the reader needs to actually read. Colors should be at least #4b5563 darkness for print.

### Engineer Button Icon Invisible (v26.15–v26.16.1)

**Problem**: The Engineer button's `fa-print` icon (U+F02F) was invisible in both Chrome and Safari, despite the glyph existing in the woff2 font file and the CSS having the correct rule. Executive's `fa-file-alt` icon worked fine.

**Root cause**: The `fa-print` CSS rule was on a separate line (line 10) of the minified CSS from the icons that were working (line 9). Additionally, the fontawesome CSS was loaded WITHOUT cache-busting version (`href="/static/css/fontawesome-subset.min.css"`) while custom.min.css had versioned URLs. Combined with browser caching, this created a persistent icon rendering failure.

**Fix applied in v26.16.2**:
- Changed Engineer icon from `fa-print` to `fa-file-lines` (FA6 name, same CSS line as working `fa-file-alt`)
- Added cache-busting version to fontawesome CSS: `{{staticVersionURL "css/fontawesome-subset.min.css" .AppVersion}}`
- Bumped woff2 font query from `?v=2` to `?v=3`

**Lesson**: When Font Awesome icons don't render, try using a class from the same CSS section as a working icon before deep-diving into font file analysis. Always version-bust ALL CSS files, not just custom.min.css.

**Why this failure persisted across multiple sessions** (self-assessment):
1. **Confirmation bias**: Each session ran `fonttools` to check the woff2, found the glyph present, and declared "fixed — must be browser caching." This was technically correct but practically useless. The icon never rendered for the user.
2. **Wrong layer of investigation**: Every session analyzed the font file (the correct glyph existed) instead of asking "why does THIS icon fail while THAT icon works?" — which would have immediately revealed the CSS line separation and missing cache-busting.
3. **Dismissing user reports**: Saying "verified, must be your browser cache" when the user reports the same bug across Chrome AND Safari is a red flag. Two browsers, same failure = the bug is real, not cached.
4. **No visual verification**: Testing confirmed the HTML rendered correctly but never verified the icon was actually VISIBLE to a human. An end-to-end test checking icon bounding box width would have caught this immediately.
5. **Missing the obvious**: The fontawesome CSS was the ONLY stylesheet without `staticVersionURL` cache-busting. custom.min.css had it. This should have been noticed on the first inspection.

**Rule for future sessions**: When a user says an icon is invisible, check THREE things: (1) Is the CSS class defined? (2) Is it on the same CSS line/section as a KNOWN WORKING icon? (3) Is the CSS file being cache-busted? Do NOT just check the font file and declare victory.

### Executive Button Color Conflict (v26.16.2)

**Problem**: Executive button used `btn-outline-warning` (amber/yellow) which visually clashed with the TLP:AMBER dropdown button immediately to its right — both were the same amber color.

**Fix v1**: Changed to `btn-outline-light` (white/clean border). Too bright — drew eyes to it first.

**Fix v2**: Created custom `btn-outline-executive` class (muted gray: #9ca3af text, #6b7280 border, subtle hover to #d1d5db). Now blends naturally with dark theme. Three buttons visually distinct: Engineer (cyan/info), Executive (muted gray), TLP:AMBER (amber/gold).

### Executive Print Font Sizes — Board Readability (v26.16.3)

**Problem**: Several Executive print sizes were too small for 40-50+ year old board members (7pt TLP note, 7.5pt labels, 8pt domain label/footer note, 10.5pt body).

**Fix**: Bumped all Executive print font sizes to meet readability floor:
- Body: 10.5pt → 11pt (with line-height 1.6 → 1.65)
- Metadata: 8.5pt → 9pt
- Labels: 7.5pt → 8.5pt
- TLP badge: 8.5pt → 9pt
- TLP note: 7pt → 8pt
- Domain label: 8pt → 9pt
- Footer: 8.5pt → 9pt
- Footer note: 8pt → 8.5pt
- Footer disclaimer: 7.5pt → 8.5pt
- h6: 9pt → 9.5pt
- Code blocks: 8pt → 8.5pt

**Rule**: Executive report minimum floor: body 11pt, small text 9pt, metadata 9pt, code 8.5pt, footer 8.5pt. Nothing below 8pt.

### Owl of Athena — Copyright Risk (v26.16.2)

**Problem**: The Owl of Athena image might have been a photograph from Wikipedia, creating potential copyright risk for a commercial product.

**Fix**: Generated an original AI-created Owl of Athena design — silver/gold metallic tones, geometric feather patterns, olive branch, coin-like circular composition on black background. Optimized from 932KB to 77KB (256x256 PNG). 100% original, no copyright concerns.

**Version**: 26.16.2

### Engineer Button Hover — Translucent Effect (v26.16.5)

**Problem**: The Engineer button (`btn-outline-info`) used Bootstrap's default solid-fill hover: the entire button background turns solid cyan/info color on hover, looking like a "blue balloon." The neighboring Executive and TLP:AMBER buttons use a subtle translucent background on hover — much more refined and consistent with the dark theme.

**Fix (attempt 1 — failed)**: Added CSS override for `.btn-outline-info:hover` with `background-color: rgba(...)`. Did NOT work because Bootstrap 5 dark theme uses CSS custom properties (`--bs-btn-hover-bg`, `--bs-btn-hover-color`, etc.) for button hover state, not direct `background-color` rules. A simple property override loses to Bootstrap's variable-driven system.

**Fix (attempt 2 — correct)**: Override Bootstrap's CSS custom properties directly on `.btn-outline-info`:
```css
.btn-outline-info {
    --bs-btn-hover-bg: rgba(13, 202, 240, 0.15);
    --bs-btn-hover-color: #5edfff;
    --bs-btn-hover-border-color: #5edfff;
    --bs-btn-active-bg: rgba(13, 202, 240, 0.25);
    --bs-btn-active-color: #5edfff;
    --bs-btn-active-border-color: #5edfff;
    transition: background-color 0.2s ease, color 0.2s ease, border-color 0.2s ease;
}
```
Also applied smooth transition to `.btn-outline-executive` for consistency.

**Lesson**: When overriding Bootstrap 5 button styles, always override the CSS custom properties (`--bs-btn-*`), not direct CSS properties. Bootstrap's `.btn` base class reads from these variables.

**CRITICAL**: After editing `custom.css`, must also run `npx csso static/css/custom.css -o static/css/custom.min.css` because the server loads `custom.min.css`, not `custom.css`.

**Design principle**: All action buttons in the report header row should use the same translucent hover pattern — subtle glow, not solid fill. This keeps the dark theme cohesive and avoids any single button visually dominating on hover.

**Version**: 26.16.5

### Naming Convention Comprehensive Sweep (Feb 15, 2026)

**Scope**: Full codebase audit to enforce IC naming convention across ALL files — not just templates, but documentation, changelogs, meta tags, manifest, LLMs files, and agent instructions.

**Files updated in sweep**:
- `static/llms.txt` — Updated tagline and features list
- `static/llms-full.txt` — Updated "Dual Intelligence Products" section with IC rationale
- `static/manifest.json` — Updated PWA description
- `go-server/templates/results_executive.html` — Fixed "View Engineer's Report" → full name, footer references, JS copyright, appendix references
- `go-server/templates/results.html` — Fixed button title attributes
- `go-server/templates/index.html` — Fixed "Executive's Intelligence Briefs" → "Executive's DNS Intelligence Briefs" in 5 locations (meta, OG, Twitter, JSON-LD, subtitle)
- `go-server/internal/handlers/changelog.go` — Fixed v26.15.26 entry title
- `EVOLUTION.md` — Fixed section headers and subtitle reference
- `LICENSING.md` — Updated frontend description
- `DOCS.md` — Updated reporting section
- `docs/FEATURE_INVENTORY.md` — Updated features list
- `replit.md` — Fixed "dual print reports" → "dual intelligence products", added naming regression check rule

**Regression prevention**: Added "Naming consistency regression check" rule to `replit.md` Known Constraints — grep for shortened variants before committing any new references.

**Key lesson**: Initial sweep missed homepage meta tags ("Executive's Intelligence Briefs" — missing "DNS") and the executive template button label ("View Engineer's Report"). These were caught by architect review. Future sweeps must check ALL five sync points per document plus all cross-references in meta tags.

**Version**: 26.16.12

---

## Multi-Format Email Header Analyzer & Password Manager Compatibility (v26.16.14)

**Date**: 2026-02-15

### Email Header Analyzer: Multi-Format Support
Added automatic format detection and extraction for the Email Header Analyzer. Previously only accepted raw pasted text and .eml uploads. Now supports:
- **Paste**: Raw headers or full emails (unchanged)
- **.eml**: Standard RFC 5322 email format (unchanged)
- **JSON**: Gmail API (`payload.headers`), Microsoft Graph API (`internetMessageHeaders`), Postmark (`Headers` array), SendGrid (`headers` map), Mailgun (`message-headers` pairs), generic (`headers` key)
- **.mbox**: Unix mailbox archives (first message extracted)
- **.txt / .headers / .log**: Plain text header exports
- **.msg**: Detected as Outlook binary with guidance to re-save as .eml

New file: `go-server/internal/analyzer/emailformat.go` — `DetectAndExtractHeaders()` function routes input through format-specific extractors. Handler updated to call this before `AnalyzeEmailHeaders()`.

### Password Manager Compatibility (1Password Focus)
Standardized all API key form fields across homepage, IP Intelligence, and results page for 1Password save/fill support:

**Changes**:
- **Removed** `data-1p-ignore` and `data-lpignore` attributes (these were blocking 1Password from saving keys)
- **Standardized field names** across all pages: `securitytrails_api_key` (was `securitytrails_key` / `st-api-key-input`), `ipinfo_access_token` (was `ipinfo_token`)
- **Labels match provider terminology**: "SecurityTrails API Key" (what SecurityTrails calls it), "IPinfo.io Access Token" (what IPinfo calls it)
- **Custom autocomplete tokens**: `autocomplete="section-dnstool securitytrails-api-key"` — prevents browser password autofill but allows 1Password to save and recognize the field
- **Proper `for` attributes** on all labels pointing to field IDs
- **Consistent `type="password"`** across all pages (homepage was inconsistent)

**Go handler updates**: `analysis.go` and `investigate.go` updated to read `securitytrails_api_key` and `ipinfo_access_token` form field names.

**JS selector updates**: `results.html` JavaScript updated from `getElementById('st-api-key-input')` to `getElementById('securitytrails_api_key')`.

**Version**: 26.16.14

### Report Integrity Hash & Header Preview (Feb 15, 2026)

**Decision**: Add SHA-256 tamper-evident fingerprint to every analysis, distinct from posture hash (drift detection). Integrity hash binds domain, analysis ID, timestamp, tool version, and canonicalized results data into a unique per-report fingerprint.

**Implementation**:
- New file: `go-server/internal/analyzer/integrity_hash.go` — `ComputeIntegrityHash()` function
- Hash stored in `domain_analyses` table (new `integrity_hash` column)
- Full hash displayed at bottom of both Engineer and Executive templates with copy-to-clipboard
- Header preview: `SHA-256: c82f✱✱✱✱ Report Integrity ↓` — first 4 chars + 4 star masks + anchor link to full hash section
- Template helper `{{substr 0 4 .IntegrityHash}}` for truncated preview
- Uses HTML entity `&#x2731;` for star masking

**Version**: 26.17.0

### Expanded Exposure Checks — Opt-In OSINT Scanner (Feb 15, 2026)

**Decision**: Add opt-in well-known misconfiguration path probing. Checks 8 common paths (/.env, /.git/config, /.git/HEAD, /.DS_Store, /server-status, /server-info, /wp-config.php.bak, /phpinfo.php) with content validation to reduce false positives.

**Implementation**:
- New checkbox in Advanced Options on homepage
- Sequential requests with 200ms delays, proper User-Agent identification
- Content validation per path type (not just HTTP 200)
- Results include severity badges, risk descriptions, and remediation guidance
- Explicit PCI DSS disclaimer: "These are OSINT collection, not ASV compliance scans"
- PCI disclaimers use collapsible FAQ-style `<details>` elements in both Public Exposure and Expanded Exposure sections

**Version**: 26.17.1

### OSINT Positioning Audit (Feb 15, 2026)

**Scope**: Comprehensive audit to ensure OSINT positioning is consistent across all discovery surfaces — homepage, reports, documentation, and LLM-facing files.

**Files updated**:
- `go-server/templates/index.html` — Meta description, keywords, JSON-LD schema updated with OSINT terminology
- `go-server/templates/results.html` — Report page meta description
- `go-server/templates/results_executive.html` — Executive report meta description
- `docs/FEATURE_INVENTORY.md` — Purpose section, design philosophy
- `static/llms.txt` — Tagline and feature descriptions
- `static/llms-full.txt` — Overview section
- `replit.md` — Overview section
- `go-server/internal/handlers/changelog.go` — Expanded Exposure entry

**Key principle**: DNS Tool is explicitly an OSINT platform. All data comes from publicly available sources — DNS queries, CT logs, RDAP, web resources. Not a penetration test, not a PCI ASV scanner, not a vulnerability assessment tool. Every data source is openly documented at `/sources`.

### Homepage FAQ Additions & Ordering (Feb 15, 2026)

**Added 4 new FAQ items** to homepage accordion:
1. "What is OSINT and how does DNS Tool use it?" — defines OSINT, explains methodology, references Shodan/Mozilla Observatory/Censys/VirusTotal
2. "Is this a PCI compliance scanner?" — explicit "No", redirects to certified ASVs (Qualys, Tenable, Trustwave), explains complementary role
3. "What data do you collect about my domain?" — lists all publicly available data sources, clarifies no intrusive scanning
4. "Is this a penetration test?" — "No", explains passive observation vs active exploitation, sidewalk analogy

**PCI FAQ moved to position #2** (right after "What is a domain security audit?") to catch compliance seekers early before they scroll past.

### Hash Preview UX Redesign (Feb 15, 2026)

**Before**: `c82faab1...` (truncated hex, unclear purpose)
**After**: `SHA-256: c82f✱✱✱✱ Report Integrity ↓` (algorithm label, star masking, clear link text)

Changes:
- Added "SHA-256:" algorithm prefix for clarity
- Reduced visible hex from 8 to 4 characters
- Added 4 star masks (✱) for visual security aesthetic
- Link text changed from bare hash to "Report Integrity ↓" with arrow indicator
- Engineer uses `text-info` (cyan), Executive uses `text-warning` (amber) for link color
- Both links smooth-scroll to the full hash section at bottom of report

### Report Integrity Link Contrast Fix (Feb 15, 2026)

**Problem**: Report header metadata bar uses `u-opacity-70` (opacity: 0.7), which reduced the "Report Integrity" link contrast below optimal levels for the target audience (40-50+ year old executives).

**Fix**:
- Added explicit `opacity: 1` on the "Report Integrity" link span to override parent opacity
- Bumped font-size from 0.72rem to 0.75rem for slightly better readability
- Executive: changed from `text-warning-emphasis` (muted amber) to `text-warning` (full amber) for stronger contrast
- Engineer: keeps `text-info` (cyan, #0dcaf0) which has ~8.6:1 contrast ratio on dark backgrounds at full opacity (WCAG AAA compliant)

**Version**: 26.17.1 (template-only changes, no version bump needed)

### CSP Compliance & XSS Hardening (Feb 15, 2026)

**Problem**: Lighthouse/PageSpeed Insights flagged CSP violations — inline `style` attributes in report templates were blocked by the nonce-based `style-src 'self' 'nonce-...'` Content Security Policy. Static code analysis also flagged `innerHTML` usage in DNS history table rendering as an XSS anti-pattern.

**Changes (v26.17.2)**:

1. **Inline style elimination**: Removed all `style=""` attributes from `results.html` (7 occurrences) and `results_executive.html` (7 occurrences). Each replaced with CSS utility classes:
   - `u-print-hash` — monospace 6pt word-break for print integrity hash
   - `u-ls-tight` — letter-spacing -0.5px for star mask characters
   - `u-fs-072rem-lh15` — compound font-size + line-height for scan-type details
   - `u-fs-078rem-break` / `u-fs-075rem-break` — font-size + word-break for hash display
   - `u-hash-label` — SHA-256 badge styling (border, color, background)
   - `u-color-heading-light`, `u-color-gray-400`, `u-color-gray-500` — text colors for integrity section
   - Existing classes reused where available: `u-fs-075rem`, `u-fs-060rem`

2. **DOM-safe DNS history rendering**: Refactored `static/js/main.js` `loadDNSHistory()` from innerHTML string concatenation to `createElement()` + `textContent` + `appendChild()`. All dynamic data now assigned via `textContent` (inherently XSS-safe). The `escapeHtml()` helper is no longer called but retained for potential use.

3. **Protocol navigation fix**: Corrected `protocolSectionMap` in results.html JavaScript:
   - `MTA-STS`: `#section-dane` → `#section-email` (MTA-STS lives in Email Security section)
   - `TLS-RPT`: `#section-dane` → `#section-email` (TLS-RPT lives in Email Security section)
   - `CAA`: `#section-dnssec` → `#section-brand` (CAA lives in Brand Security section)

**Version**: 26.17.2

---

## Mail Transport Security Redesign (v26.18.0)

**Date**: 2026-02-15

**Problem**: The "Live SMTP TLS Validation" section attempted direct SMTP probes to port 25, which fails on all major cloud platforms (AWS, GCP, Azure, Replit) that block outbound SMTP. This produced misleading "connection failed" errors that were hosting constraints, not security findings.

**Solution**: Redesigned to a standards-aligned three-tier architecture:

1. **Policy Assessment** (Primary) — Evaluates MTA-STS and DANE/TLSA DNS policies per RFC 8461 and RFC 7672. This is the authoritative method per NIST SP 800-177 Rev. 1. Status vocabulary: `enforced` / `monitoring` / `opportunistic` / `none`.

2. **Telemetry Indicators** — Reports TLS-RPT (RFC 8460) configuration status, cross-referenced from the Email Security section.

3. **Live Probe** (Supplementary) — SMTP STARTTLS probe, now controlled by `SMTP_PROBE_MODE` environment variable:
   - `skip` (default, production) — Shows "Skipped" status with explanation
   - `force` (development/testing) — Attempts actual probe

**Data model**: Versioned format (v2) with `policy`, `telemetry`, `probe` objects. Backward-compatible with stored v1 scans via template guards.

**Template changes**:
- Engineer's report: Section renamed "Mail Transport Security", three sub-sections with role badges (PRIMARY/SUPPLEMENTARY)
- Executive brief: Row renamed "Mail Transport" with "Policy-assessed" annotation
- MTA-STS cross-reference updated to point to "Mail Transport Security"

**Design rationale**: RFC 8461 (MTA-STS) was specifically created because SMTP STARTTLS is vulnerable to downgrade attacks — the DNS policy IS the security mechanism. Direct SMTP probing is supplementary validation, not primary assessment.

**Future**: Data model designed to accommodate external VPS probe nodes (Hetzner, OVH) as industry-standard multi-vantage approach.

---

## Session: February 15, 2026 (continued — v26.19.0)

### DKIM Gateway Inference & Pipeline Structural Refactor

**Problem**: False "Third-Party Only" DKIM badge for domains routing all mail through a security gateway. Example: fugro.com has MX → Proofpoint, SPF → Proofpoint, but DKIM selectors `selector1`/`selector2` prove Microsoft 365 is the actual mailbox platform. The old logic couldn't see through the gateway because both MX and SPF pointed to Proofpoint, so `resolveProviderWithGateway` never triggered the gateway+mailbox split.

**Fix (v26.18.1→v26.19.0)**: Two changes:

1. **`inferMailboxBehindGateway`**: Post-DKIM inference step. After all selectors are scanned and `foundProviders` is built, if the primary provider is a known security gateway and DKIM selectors reveal exactly one mailbox-class provider behind it, re-attribute primary to the mailbox provider and set gateway correctly. For multiple mailbox providers, add an explanatory note but don't guess.

2. **Typed `ProviderResolution` struct**: Replaced `map[string]any` return from `detectPrimaryMailProvider` and `interface{}` for gateway with a typed struct (`Primary string`, `Gateway string`, `SPFAncillaryNote string`, `DKIMInferenceNote string`). This eliminates silent type drift, makes the data flow self-documenting, and prevents future coupling errors.

3. **`reclassifyAmbiguousSelectors`**: After gateway inference changes the primary, ambiguous selectors (selector1, selector2, s1, s2, default, k1, k2) are re-evaluated against the new primary. This fixes a hidden dependency where selectors were classified against the pre-inference primary and never updated.

**Architectural lesson**: The pipeline had implicit ordering dependencies — selector classification happened with the MX/SPF-derived primary, then inference changed the primary, but selectors weren't re-evaluated. Adding good logic shouldn't break existing good logic. The structural fix (typed struct + reclassification pass) makes additions safe by design rather than requiring manual trace of side effects.

**`mailboxProviders` map**: Microsoft 365, Google Workspace, Zoho Mail, Fastmail, ProtonMail, Cloudflare Email. These are the providers that can sit behind a security gateway.

**Pipeline order (post-refactor)**:
1. `detectPrimaryMailProvider` → `ProviderResolution` (MX + SPF signals)
2. `processDKIMSelector` (concurrent) → classify selectors against initial primary
3. `collectFoundProviders` → build provider set from selectors
4. `inferMailboxBehindGateway` → if primary is gateway, infer mailbox from DKIM
5. `reclassifyAmbiguousSelectors` → re-evaluate ambiguous selectors against final primary (only if primary changed)
6. `collectFoundProviders` (again) → rebuild provider set with reclassified data
7. `attributeSelectors` / `checkPrimaryHasDKIM` → final attribution with correct primary

---

## Session: February 17, 2026 (v26.19.18)

### Changes
1. **Big Questions visual pop**: Enhanced CSS for `.section-question` (cyan accent, text shadow) and `.protocol-question-text` (left border, background highlight) — questions now visually stand out as the core product identity.
2. **Loading screen rebranding**: Changed "Posture scoring & remediation" to "Classifying & interpreting intelligence" to match ICIE identity.
3. **Report button UX fix**: Engineer/Executive buttons now show Print icon on current report and Navigate icon for other report — no unwanted print dialogs.
4. **Null MX remediation bug**: Domains with RFC 7505 null MX were classified "High Risk" but got zero Priority Action fixes because `GenerateRemediation` skipped all email fixes when `isNoMailDomain` was true. Added `appendNoMailHardeningFixes` providing SPF `-all` and DMARC `reject` fixes specifically for null MX domains.
5. **DMARC monitoring phase expansion**: `evaluateDeliberateMonitoring` now also covers `quarantine` at partial enforcement (`pct < 100`) with `rua` reporting, not just `p=none`.
6. **Homepage rebranding**: "What We Analyze" → "Intelligence Collection Vectors"; subtitle reframed from checker to OSINT language.
7. **SEO/Schema cleanup**: Page title, OG/Twitter meta, JSON-LD schema all updated to drop "Checker" and use "Domain Security Audit | OSINT DNS Intelligence Reports" identity.
8. **Maintenance tag**: Configurable `MAINTENANCE_NOTE` env var renders a small professional badge next to version in report header. Driven by env var so it can be toggled without code changes.
9. **Roadmap items 9-14 stored**: Zone file export/import, raw intelligence access, ISC recommendation path, one-liner verification, Email Header Analyzer matrix, probe node integration — all documented in `replit.md` Phase 2 roadmap.

---

## Failures & Lessons Learned — Quick Reference

This table is a compact summary of all documented failures. For detailed root cause analysis and failed approaches, see the "Failures & Lessons Learned — Detailed Analysis" section above.

| Date | Mistake | Root Cause | Correct Solution |
|------|---------|------------|------------------|
| 2026-02-14 | CSP blocked inline onclick handlers | Used `onclick` in HTML | Use `id` + `addEventListener` in `<script nonce>` blocks |
| 2026-02-14 | Font Awesome icons missing after subset | Regenerated woff2 without verifying glyphs | Always verify with fonttools before regenerating |
| 2026-02-14 | PDF title wrong format | `<title>` tag didn't follow naming convention | Format: "Report Type — domain - DNS Tool" (e.g., "Engineer's DNS Intelligence Report — example.com - DNS Tool") |
| 2026-02-15 | Intelligence naming convention established | IC document types: Report (long) vs Brief (short). Possessive form. "DNS Intelligence" not "Security Intelligence" (MI5's name). | See EVOLUTION.md "Intelligence Document Naming Convention (v26.16.11)" section |
| 2026-02-14 | Executive print text too small | Font sizes below 8pt | Minimum: body 11pt, small 9pt, code 8.5pt, footer 8.5pt |
| 2026-02-14 | Executive button too bright (btn-outline-light) | White text/border on dark theme | Use custom `btn-outline-executive` with muted gray #9ca3af |
| 2026-02-14 | Engineer button solid hover fill | Bootstrap default btn-outline-info hover | Override `--bs-btn-hover-bg` CSS variable (NOT direct `background-color`) |
| 2026-02-14 | CSS changes not appearing on screen | Edited `custom.css` but server loads `custom.min.css` | MUST run `npx csso static/css/custom.css -o static/css/custom.min.css` after every CSS edit |
| 2026-02-14 | First CSS override attempt failed | Used `background-color` property (loses to Bootstrap's CSS variable system) | Override `--bs-btn-*` CSS custom properties, not direct properties |
| 2026-02-15 | Naming sweep missed meta tags and button labels | Checked templates but not all 5 sync points per product | Always check: `<title>`, print header, screen `<h1>`, OG/Twitter meta, AND button/link labels. Grep for shortened variants. |
| 2026-02-15 | TLP button colors invisible (no colored border) | Bootstrap's `.btn.dropdown-toggle` specificity overrides single-class `.btn-tlp-red` | Use double-class `.btn.btn-tlp-red` selector for ALL TLP button variants. Same pattern as the Executive button fix. |
| 2026-02-15 | TLP badge colors invisible in dropdown | Bootstrap's `.badge` default background overrides `.tlp-badge-red` | Use `.dropdown-menu .badge.tlp-badge-red` selector (higher specificity). |
| 2026-02-15 | TLP dropdown stays open after selection | `e.preventDefault()` in click handler prevents Bootstrap auto-close | Call `bootstrap.Dropdown.getInstance(btn).hide()` after updating UI state. |
| 2026-02-15 | CSS edits not visible despite minify+restart | `AppVersion` unchanged so `staticVersionURL` cache-buster serves stale CSS | MUST bump `AppVersion` in config.go after CSS changes (triggers new `?v=` query string). |
| 2026-02-15 | AppVersion bump didn't take effect | Changed config.go but didn't rebuild Go binary. `main.py` does `os.execvp("./dns-tool-server")` — it runs a pre-compiled binary, not `go run`. | After ANY Go code change: `cd go-server/cmd/server && go build -o /home/runner/workspace/dns-tool-server .` then restart workflow. |
| 2026-02-15 | CSP blocked inline style attributes | Used `style=""` in HTML templates with nonce-based `style-src` CSP | Move all inline styles to CSS utility classes. Inline `style` attributes cannot carry nonces. |
| 2026-02-15 | innerHTML XSS anti-pattern in DNS history | Built HTML via string concatenation + innerHTML | Use createElement() + textContent + appendChild() for DOM-safe rendering |
| 2026-02-15 | Protocol links navigated to wrong sections | protocolSectionMap had incorrect mappings for MTA-STS, TLS-RPT, CAA | Verify section IDs match actual template structure: MTA-STS/TLS-RPT → #section-email, CAA → #section-brand |
| 2026-02-15 | DKIM "Third-Party Only" false positive behind gateways | Pipeline classified selectors against pre-inference primary, never re-evaluated after gateway inference changed primary. `map[string]any` and `interface{}` masked type dependencies. | Use typed `ProviderResolution` struct. Add `reclassifyAmbiguousSelectors` pass after inference. Rebuild `foundProviders` before final attribution. Pipeline stages must be idempotent to primary changes. |
| 2026-02-16 | .tech domain shows "Registry Restricted" when registrar is available via RDAP | Two compounding bugs: (1) WHOIS for .tech returns empty response, `isWhoisRestricted` treated ANY response <50 chars as "registry restricted" regardless of TLD; (2) RDAP telemetry cooldown skipped RDAP entirely after transient failures, forcing the broken WHOIS path. | **WHOIS fix**: Only mark "restricted" for known restricted TLDs (es, br, kr, cn, ru). Empty WHOIS from other TLDs = "failed", not "restricted". **RDAP fix**: Never skip RDAP for registrar lookups — registrar is critical data. Log cooldown warnings but still attempt. **Golden rules**: (1) "Registry Restricted" label MUST only appear for TLDs with confirmed registry access policies, never as a fallback for failed lookups. (2) RDAP is the primary registrar source; WHOIS is fallback, not equal. (3) Telemetry cooldown must not block critical data paths. |
| 2026-02-16 | RDAP lookup only tried one endpoint, silently blocked by SSRF validation in production | Two bugs: (1) `rdapLookup` selected ONE endpoint and gave up on first failure — no retry. Python tool iterates ALL IANA endpoints + rdap.org fallback. (2) `ValidateURLTarget` returned false when DNS resolution for the RDAP server failed (timeout), silently blocking the HTTP request with misleading "SSRF protection" error. | **Multi-endpoint fix (v26.19.10)**: Refactored `rdapLookup` into `buildRDAPEndpoints` (deduplicates: hardcoded → IANA map → rdap.org fallback) + `tryRDAPEndpoint` (iterates all, only records telemetry failure on last attempt). Matches Python tool's resilience pattern. **SSRF fix**: `ValidateURLTarget` now returns `true` when DNS lookup fails — only blocks on positive private IP detection. DNS failure ≠ SSRF threat; let the HTTP client handle connection errors naturally. **Build path**: Binary must be built to `./dns-tool-server` (not `./go-server/dns-tool`) — `main.py` does `os.execvp("./dns-tool-server", ...)`. |
| 2026-02-16 | Registrar name never saved to database despite RDAP success | `getStringFromResults(results, "registrar_info", "registrar_name")` used wrong key — the result map uses `"registrar"`, not `"registrar_name"`. Every scan since the field was added had empty `registrar_name` in the database. | **Fix (v26.19.11)**: Changed to `getStringFromResults(results, "registrar_info", "registrar")`. Confirmed: scan #746 now saves "Amazon Registrar, Inc." to the database. Note: production RDAP failures (scan #942) are transient networking issues in Replit's deployment environment, not code bugs. |
| 2026-02-16 | RDAP transient production failures despite multi-endpoint — double DNS resolution, no retries, stale connections | Three root causes compared to Python CLI: (1) SSRF `ValidateURLTarget` resolves RDAP hostname via `net.LookupHost()` BEFORE the HTTP client resolves again — double DNS resolution in constrained networks. (2) Each endpoint got exactly one attempt — no retry with backoff. (3) Long-running server's connection pool had stale connections vs. Python CLI's fresh-process approach. | **Fix (v26.19.12)**: (1) Created dedicated `NewRDAPHTTPClient()` with `DisableKeepAlives: true` (fresh connections like CLI), 15s timeout, `GetDirect()` method that bypasses SSRF preflight for known-safe RDAP endpoints + sends `Accept: application/rdap+json`. (2) Parallel endpoint attempts — all endpoints fire simultaneously, first success wins, others cancelled. (3) Retry with exponential backoff per endpoint (up to 2 retries, 200ms/400ms). (4) Removed registrar from "Partial Results" error banner — contextual data failures shouldn't alarm users. Registrar box still shows "Unknown" visually for internal testing, and WARN-level logging catches failures. **ICIE alignment**: RDAP is Tier 4 contextual intelligence, not Tier 1-2 security protocol — its failure should not be presented as a security analysis error. |
| 2026-02-17 | Stub architecture audit and DKIM selector extraction bug | commands.go DKIM extraction tried to cast selectors as `[]any` but dkim.go returns `map[string]any`; DMARC external report auth looked under `dmarc` key instead of top-level `dmarc_report_auth`; selector names include `._domainkey` suffix causing doubled paths in verification commands; stub registry listed 3 files (commands.go, edge_cdn.go, saas_txt.go) that are now fully implemented. | **Fixes**: (1) DKIM extraction handles both map and slice types, strips `._domainkey` suffix. (2) DMARC report auth checks top-level key first. (3) Stub registry cleaned to 10 actual stub files. (4) `ai_surface/http.go` fetchTextFile returns empty string instead of error for graceful degradation. (5) Maintenance badge improved: custom CSS with readable gold-on-dark styling, capitalized "Accuracy Tuning". |

---

## Stub Architecture — Two-Repo Design (v26.19.20)

### Overview
The project uses a two-repository architecture:
- **DNS Tool Web** (public, open-source core): Contains the full application with stub files that stand in for private intelligence
- **dnstool-intel** (private): Contains proprietary intelligence data — provider databases, detection patterns, advanced analysis logic

### Design Contract
Every stub file MUST:
1. Return safe, non-nil defaults (empty maps, empty slices, false booleans)
2. Never return errors that propagate to template rendering
3. Maintain correct function signatures matching the orchestrator's expectations
4. Allow the UI to render gracefully — sections may show "not found" or "standard" but must never crash or silently disappear

### Current Stub Registry (10 files)

| File | Purpose | Degradation Behavior |
|------|---------|---------------------|
| `ai_surface/http.go` | HTTP fetcher for web content | Returns empty string, no error — scanners see empty content |
| `ai_surface/llms_txt.go` | llms.txt detection | Returns `found: false` — section renders "not found" |
| `ai_surface/robots_txt.go` | AI crawler detection in robots.txt | Returns empty arrays — section renders "no crawlers detected" |
| `ai_surface/poisoning.go` | AI recommendation poisoning IOCs | Returns `ioc_count: 0` — section renders "no indicators found" |
| `confidence.go` | Confidence level constants and helpers | Fully functional — defines Observed/Inferred/ThirdParty levels |
| `dkim_state.go` | DKIM state classification enum | Fully functional — classifies DKIM status from protocol state |
| `infrastructure.go` | Provider detection databases | Enterprise providers detected; managed/self-hosted/government return nil |
| `ip_investigation.go` | IP relationship analysis | Returns minimal skeleton — separate investigation page shows basic info |
| `manifest.go` | Feature parity manifest | Returns empty — manifest-dependent features don't render |
| `providers.go` | Provider intelligence boundaries | Empty provider maps — boundary functions return false/nil |

### Files NO LONGER Stubs (removed from registry 2026-02-17)
- `commands.go` — Fully implemented with 19 protocol sections, 25+ verification commands
- `edge_cdn.go` — Fully implemented with CDN/edge detection patterns
- `saas_txt.go` — Fully implemented with SaaS TXT footprint extraction

### Golden Rule Tests
- `TestGoldenRuleStubRegistryComplete` — detects unregistered stub files
- `TestGoldenRuleNoProviderIntelligenceInPublicFiles` — prevents IP leakage into non-stub files
- `TestGoldenRuleStubBoundaryFunctionsRegistered` — ensures boundary functions stay in providers.go

### Rules for Adding New Stubs
1. Add the "stub implementations" comment on line 3
2. Register the file in ALL THREE `knownStubFiles` maps in `golden_rules_test.go`
3. Return safe defaults — NEVER return errors from stub functions
4. Write a golden rule test verifying the stub's degradation behavior

### Python Files (Not Stubs)
- `main.py` — Process trampoline only; `os.execvp` replaces Python process with Go binary. No Flask, no Python logic at runtime.
- `go-server/scripts/audit_icons.py` — Dev-only helper for Font Awesome icon subset auditing. Never executed in production.

---

## Documentation & Citation Standard Decision (2026-02-17)

### Decision: NIST SP 800-series Style
After evaluating APA, Chicago/Turabian, IEEE, NIST SP 800, and ICD (Intelligence Community Directives), the project adopts **NIST SP 800-series style** as the official documentation and citation standard, augmented with IEEE-style numeric citations for RFC and protocol references.

### Rationale
| Standard | Verdict | Why |
|----------|---------|-----|
| APA | Rejected | Academic/social science tone undermines security credibility |
| Chicago/Turabian | Rejected | Humanities/publishing voice, not security operations |
| IEEE | Partial adoption | Good for numbered protocol references; too engineering-paper-style for the full document voice |
| ICD | Rejected | Government intelligence classification handling beyond our scope; could confuse commercial positioning |
| **NIST SP 800** | **Adopted** | Natural alignment with NIST/CISA/RFC ecosystem; authoritative for executives and technical users; matches "Decision-Ready Intelligence" framing |

### Style Rules (canonical reference in replit.md)
1. Document structure: Summary → Findings → Evidence → Impact → Recommendations
2. Tone: Authoritative, observation-based, factual. No hedging.
3. Technical references: IEEE numbered citations for RFCs/standards
4. Terminology: NIST/CISA vocabulary (control, finding, observation, recommendation, risk level)
5. Visual identity: NIST governs content structure, not visual design — dark theme and hacker fonts remain

### Badge Update (same session)
Accuracy Tuning badge restyled with amber pill-shaped outline (`border: 2px solid`, `border-radius: 999px`, subtle `box-shadow` glow) for notice/warning visual weight.

---

## Session: February 17, 2026

### Two-Repo Boundary Refactor — Build Tag Strategy

**Problem**: All recent development went into the public DnsToolWeb repo. Intelligence data (CDN ASN maps, SaaS regex patterns, enterprise provider databases, AI crawler lists) was fully exposed in public stub files with zero actual stubbing. The private `dnstool-intel` repo (last updated Feb 14) had drifted completely.

**Solution**: Adopted HashiCorp-style Go build-tag pattern (`//go:build intel` / `//go:build !intel`) with three-file split:
- `<name>.go` — Framework only (types, constants, utilities). No build tag. Always compiled.
- `<name>_oss.go` — `//go:build !intel`. Empty maps, safe stub returns. Ships in public repo.
- `<name>_intel.go` — `//go:build intel`. Full intelligence. Lives in private `dnstool-intel` repo only.

### Files Split (10 files → 30 files)

| Original File | Framework | OSS Stub | Intel (staged) |
|---|---|---|---|
| `edge_cdn.go` | Types only | Empty CDN/cloud maps, stub detection | 22 CDN ASNs, 15 cloud ASNs, 30 PTR patterns, 36 CNAME patterns |
| `saas_txt.go` | `saasPattern` type, `truncateRecord()` | Empty patterns, stub extraction | 48 SaaS TXT regex patterns |
| `infrastructure.go` | `providerInfo`, `infraMatch`, `dsDetection`, utilities | Empty provider maps (14), stub functions (34) | 22 enterprise, 10 legacy, 28 MX, 24 NS, 22 web, 14 PTR providers |
| `providers.go` | 5 types, 11 capability constants, 28 category constants | Vendor names, empty maps (6), stub functions (3) | Full provider databases |
| `ip_investigation.go` | `IPRelationship`, regex vars, utilities | Stub investigation functions (17) | Full IP investigation |
| `ai_surface/http.go` | Package decl | Stub `fetchTextFile()` | Full HTTP fetcher |
| `ai_surface/llms_txt.go` | Package decl | Stub LLMs.txt detection (4 functions) | Full LLMs.txt analysis |
| `ai_surface/robots_txt.go` | `robotsDirective` type | Empty crawler list, stub detection (4) | 15 AI crawler patterns |
| `ai_surface/poisoning.go` | `truncate()` utility | Stub IOC/prompt detection (6) | Full poisoning detection |
| `manifest.go` | `ManifestEntry` type, `GetManifestByCategory()` | Empty manifest, stub `init()` | Full feature parity manifest |

### Files Reclassified as Pure Framework (no split needed)
- `confidence.go` — Constants and utility functions only. Removed incorrect "stub" header.
- `dkim_state.go` — Type definitions and classification logic. Removed incorrect "stub" header.

### Test Infrastructure Changes
- Created `golden_rules_intel_test.go` (`//go:build intel`) — 9 tests that depend on populated intelligence maps
- Updated stub registry in 3 test functions to reflect new `_oss.go` file names
- All remaining golden rule tests pass in OSS mode

### Documentation Created
- `docs/BOUNDARY_MATRIX.md` — Comprehensive analysis of 123 FRAMEWORK, 61 INTELLIGENCE, 26 DUAL symbols across all files
- `docs/BUILD_TAG_STRATEGY.md` — Build-tag strategy, three-file pattern specification, CI matrix

### Intel Staging
All `_intel.go` files staged at `docs/intel-staging/` for transfer to private `dnstool-intel` repo:
- `edge_cdn_intel.go`, `saas_txt_intel.go`, `infrastructure_intel.go`, `providers_intel.go`, `ip_investigation_intel.go`, `manifest_intel.go`
- `ai_surface/http_intel.go`, `ai_surface/llms_txt_intel.go`, `ai_surface/robots_txt_intel.go`, `ai_surface/poisoning_intel.go`

### scanner.go Split (completed 2026-02-17)
`ai_surface/scanner.go` was refactored: `aiCrawlers` var removed, replaced with `GetAICrawlers()` function call. `scanner_oss.go` returns empty slice, `scanner_intel.go` (in private repo) returns full 15-crawler list. All 11 boundary files now fully split.

### Intel Transfer (completed 2026-02-17)
All 11 `_intel.go` files transferred to `careyjames/dnstool-intel` private repo via GitHub API. `docs/intel-staging/` deleted from public repo. No intelligence data remains in public repo.

### Sync Workflow for Private Repo (completed 2026-02-17)
All files transferred via GitHub API. Manual copy no longer needed.

---

## Session: 2026-02-17 (continued) — Boundary Integrity Test Suite

### Problem
After major two-repo refactoring, Ahrefs SEO health dropped from 100% to 44%. Big architectural changes are risky — regressions cost $100-200/day. Need automated guardrails to prevent boundary violations, intelligence leaks, and stub contract breakage.

### Solution: Comprehensive Boundary Integrity Tests
Created two test files that enforce 11 verification categories across all 11 boundary files:

**Test Files:**
- `go-server/internal/analyzer/boundary_integrity_test.go` — 6 analyzer boundaries
- `go-server/internal/analyzer/ai_surface/boundary_integrity_test.go` — 5 ai_surface boundaries

**What They Check:**
1. File Presence — framework.go + _oss.go exist for every boundary
2. No Intel in Public Repo — no _intel.go files anywhere in public codebase
3. Build Tags — _oss.go has `//go:build !intel`, framework has none
4. Stub Functions Defined — all expected functions in _oss.go
5. Stub Variables Defined — all expected maps/slices initialized
6. No Intelligence Leakage — known intel tokens (crawler names, provider domains) absent from public files
7. Safe Defaults — stubs return non-nil, never error, never panic
8. No Duplicate Functions — no function defined in both framework and stub
9. Correct Package — all files declare correct Go package
10. Boundary Inventory — count check catches unregistered new boundaries
11. No intel-staging — directory must not exist

**Run Commands:**
```bash
go test ./go-server/internal/analyzer/ -run "TestBoundary" -v
go test ./go-server/internal/analyzer/ai_surface/ -run "TestAISurface" -v
go test ./go-server/... -count=1
```

### golden_rules_test.go Fix
Updated `TestGoldenRuleStubBoundaryFunctionsRegistered` to read both `providers.go` AND `providers_oss.go` when checking for boundary functions — the three-file split moved functions from `providers.go` to `providers_oss.go`.

### Lesson Learned
When splitting a file into three-file pattern, any test that reads the original file by name must be updated to also read the new _oss.go file. Tests that hardcode filenames are fragile when architecture changes.

### Version Bump Protocol (established 2026-02-17)
When user says "version up," the version MUST be bumped BEFORE publishing. Version lives in ONE place:
- `go-server/internal/config/config.go` → `AppVersion` field

This single source propagates to:
- Every HTML template via `AppVersion` template variable (navbar badge, footers)
- Service worker cache name via `SW_VERSION_PLACEHOLDER` replacement in `static.go`
- Analysis report metadata (`_tool_version`, integrity hash)
- PWA cache busting (old caches cleared when version changes)

**Missed version bump on v26.19.21 → published stale version. Cost: user frustration + republish. Never skip again.**

### Homebrew Distribution (planned)
User confirmed DNS Tool will be distributed via Homebrew for macOS/Linux CLI installation. This means:
- Versioning must be strict semver-compatible
- All docs, paths, and metadata must be clean and production-ready
- The single-source version in `config.go` will need to match Homebrew formula versions
- Build artifacts will need to be reproducible and properly tagged

### Cleanup: dnstool-intel-staging/ (2026-02-17)
Removed leftover `dnstool-intel-staging/` directory from project root. Was a temporary scratch folder from a previous session's work — contained duplicate provider files already transferred to private repo. Added path to boundary integrity test `TestBoundaryIntegrity_NoIntelStagingDirectory` so it gets caught automatically in the future.

### Test Data Policy (decided 2026-02-17)
**Rule**: Automated/internal test runs must NOT pollute the public analysis history. Test entries (e.g., `example.com` from Playwright) must be cleaned up before shipping.
**Exception**: Curated showcase domains (e.g., `nlnetlabs.nl` for DANE, `ietf.org` for DNSSEC best practices) can be intentionally pushed to the top of history as educational examples — these demonstrate the tool's capabilities to new users.
**Rationale**: Users notice inconsistent history ("10 minutes ago it looked different"), and internal test noise undermines trust. Keep history clean and intentional.
**Action taken**: Deleted 2 `example.com` entries created by automated testing agent.

### Safari Loading Overlay Animation Fix (2026-02-17)
**Problem**: Safari's WebKit engine does not restart CSS animations when an element transitions from `display: none` (Bootstrap `d-none`) to `display: flex`. The loading overlay appeared (globe icon, text, dots visible) but all animations were frozen — no spinning, no pulsing, no bouncing dots.
**Root cause**: WebKit optimization — animations defined on elements that start hidden are never initialized, and removing `display: none` doesn't trigger re-initialization.
**Fix**: Created `showOverlay()` function in `main.js` that:
1. Removes `d-none` class
2. Forces reflow via `void overlay.offsetWidth`
3. Resets `animation` property on all animated children (spinner, dots) to force WebKit to reinitialize
Applied `showOverlay()` to all overlay trigger points: index.html form submit, results.html re-analyze button, history.html re-analyze and view buttons, investigate.html form submit.
**Also fixed**: "Analyze the root domain instead" link on subdomain results pages — was a plain `<a href>` with no overlay trigger. Now intercepts click, shows overlay with animation, then navigates. This fixes the "long wait with nothing happening" experience in Safari when clicking that link.
**Lesson**: Every `classList.remove('d-none')` on an animated overlay must go through `showOverlay()` for Safari compatibility.

### Per-Section Maintenance Tags System (2026-02-17)
**Purpose**: Transparent development status badges on individual report sections. When a section is actively being tuned or has been repeatedly fixed, a small wrench badge appears in the section's card header showing "Accuracy Tuning" (or custom label).

**Implementation**:
- `sectionTuningMap` in `config.go`: Central map of section ID → label. Uncomment to activate.
- `.u-section-tuning` CSS class in `custom.css`: Gold wrench badge, hidden in print (`@media print { display: none }`).
- Template badges in `results.html`: All 11 section headers have conditional `{{if and .SectionTuning (index .SectionTuning "SECTION_ID")}}` guards.
- Executive template intentionally omits badges — board-level readers don't need development status info.

**Active sections** (based on EVOLUTION.md history of repeated fixes):
| Section | Reason for Tag |
|---------|---------------|
| `email` | SPF provider detection (MX corroboration, ancillary senders), DKIM gateway inference, pipeline structural refactor, protocol navigation fixes — multiple rounds Feb 14-17 |
| `brand` | BIMI recommendation logic correction, isBIMICapableProvider stub default fix, CAA protocol navigation fix |
| `ai` | 5 boundary stub files, ongoing boundary architecture work, fetchTextFile error handling |
| `smtp` | Complete redesign from live SMTP probes to standards-aligned three-tier architecture (v26.18.0) |
| `infra` | RDAP failures across 3+ rounds (v26.19.10, .11, .12): multi-endpoint, SSRF bypass, parallel attempts, registrar save bug |

**How to manage**: Edit `sectionTuningMap` in `config.go`, rebuild, restart. Section IDs: email, dane, brand, securitytxt, ai, secrets, web-exposure, smtp, infra, dnssec, traffic.

### OG/SERP Title Update (2026-02-17)
**Change**: "DNS Tool — Domain Security Audit | Engineer's Report & Executive's Brief" → "DNS Tool — Domain Security Intelligence | OSINT Reports"
**Updated in**: `<title>`, OG title, Twitter title, JSON-LD schema name — all 4 sync points aligned.
**Rationale**: Includes "Intelligence" keyword (matches report naming convention), stays within ~55 char SERP limit for full visibility, drops possessives for brevity in title context (full possessive form retained in report headers).

### Ahrefs Site Audit Fix — SEO Hardening (2026-02-17)
**Problem**: Ahrefs site audit (Feb 17 crawl) found 24 actual issues including 105 internal 404 pages, 105 canonical-points-to-4XX, 49 indexable pages not in sitemap, long meta descriptions, schema.org validation errors, and orphan pages.

**Root cause analysis**:
- **105 404s + canonical-to-4XX**: Old analysis result URLs (IDs that were deleted from DB) being crawled. Analysis pages had `rel=canonical` pointing to themselves and were indexable — so Ahrefs indexed them, then found them gone.
- **49 indexable not in sitemap**: Analysis result pages were indexable but not in sitemap (correct — they're ephemeral).
- **Meta descriptions too long**: 4 pages exceeded 160 chars (index.html 368, email_header 225, security_policy 180, results.html 171).
- **Title too long**: index.html title was 74 chars (Google truncates at ~60).
- **Schema.org errors**: `slogan` and `applicationSubCategory` are not valid properties for `WebApplication` type.
- **Orphan pages**: `/security-policy` had no internal links.
- **Compare pages**: Were indexable with canonical tags but are dynamic/user-specific content.

**Fixes applied**:
1. **Analysis pages noindex**: Added `<meta name="robots" content="noindex, nofollow">` to `results.html`, removed `rel=canonical`. These are ephemeral reports — search engines shouldn't index individual analyses. Executive template already had noindex.
2. **Compare pages noindex**: Replaced canonical with noindex on `compare.html` and `compare_select.html` (dynamic comparison pages).
3. **Meta descriptions trimmed**: All 4 pages trimmed to <155 chars while retaining key terms.
4. **Title shortened**: `DNS Tool — Domain Security Intelligence | OSINT Reports` (~55 chars, within Google's display limit).
5. **Schema.org fixed**: Removed invalid `slogan` and `applicationSubCategory` properties from JSON-LD.
6. **Sitemap cleaned**: Removed `/compare` (now noindex). 8 indexable pages remain in sitemap.
7. **Missing canonical tags added**: `/history`, `/stats`, `/email-header`, `/investigate` now have proper canonical tags.
8. **Orphan page fixed**: Added footer link row (Security Policy, Changelog, Sources) to `_footer.html` — appears on every page.

**Expected Ahrefs improvement on next crawl**:
- 105 404s → Will gradually de-index (analysis pages now noindex, no new ones will be indexed)
- Canonical-to-4XX → Eliminated (no more canonical on analysis pages)
- Indexable not in sitemap → Should drop to ~0 (all indexable pages now in sitemap)
- Meta descriptions → 0 "too long" issues
- Title too long → 0
- Schema.org errors → Reduced (removed invalid properties)
- Orphan pages → 0 (footer links added)

### Email Header Analyzer — Subject Line & Spam Vendor Hardening (2026-02-17)

**Problem**: A tech support scam email sent FROM Microsoft's own infrastructure (microsoftonline.com) passed SPF/DKIM/DMARC legitimately and was reported as "No Issues Observed" by the header analyzer. The email had clear scam signals: phone number with homoglyph obfuscation ("983 22O2 4O6" using letter O instead of zero), fake PayPal payment claim ("Pay PaI 699.99 USD" using capital I instead of lowercase l), and Proofpoint had already flagged it as spam via `X-CLX-Spam: true`.

**Root cause**: The analyzer only checked authentication (SPF/DKIM/DMARC alignment) and a narrow set of spam headers (`X-Spam-Flag`, `X-Spam-Status`, Apple headers). It had no subject line analysis capability and was blind to major email security vendor headers (Proofpoint, Barracuda, Microsoft SCL, Mimecast).

**Fixes applied**:

1. **Expanded spam header detection**: Added detection for Proofpoint (`X-CLX-Spam`, `X-CLX-Score`, `X-Proofpoint-Spam-Details-Enc`), Barracuda (`X-Barracuda-Spam-Status`, `X-Barracuda-Spam-Score`), Microsoft (`X-Forefront-Antispam-Report` SCL score), and Mimecast (`X-Mimecast-Spam-Score`). SCL >= 5 triggers spam flag automatically.

2. **Subject line scam analysis** (new capability):
   - **Phone number detection**: Finds phone numbers in subject lines; escalates to danger if letter-for-digit substitution detected (O→0, I→1)
   - **Payment amount detection**: Flags monetary amounts ($xxx.xx USD) — classic fake invoice/charge trigger
   - **Homoglyph detection**: Normalizes look-alike characters (O→0, I→l, Cyrillic→Latin) and compares to original to detect obfuscation
   - **Scam phrase detection**: Matches known subject line patterns ("you authorized", "payment confirmation", "account suspended", etc.)

3. **Improved brand mismatch detection**:
   - Now checks subject line after homoglyph normalization (catches "Pay PaI" → "paypal")
   - Added more brands: Netflix, Bank of America, Wells Fargo, Chase, Geek Squad, Norton, McAfee
   - Domain comparison is now whitespace-insensitive

4. **New UI section**: "Subject Line Analysis" card with red border and scam indicator badges, positioned between header findings and body analysis

5. **Updated verdict logic**: Subject line danger indicators now factor into suspicious/caution classification. New verdict message for spam + subject scam combo.

6. **New Big Question**: "All authentication passed — so why are there scam indicators in the subject?" explains the legitimate-infrastructure-abuse attack pattern.

**Lesson learned**: Authentication (SPF/DKIM/DMARC) verifies infrastructure, not intent. Scammers increasingly use legitimate services to send authenticated emails. Subject line analysis is critical for detecting weaponized notifications.

**Globalping.io evaluation** (2026-02-17): Evaluated as potential intelligence source for DNS propagation verification from globally distributed probes. Offers DNS, ping, traceroute, HTTP, MTR from hundreds of locations worldwide. Free tier: 250 tests/hour. Would add "Is this domain resolving consistently worldwide?" capability. Added to roadmap — not implemented yet. **Architect decision**: Complementary to the existing SMTP port 25 probe, NOT a replacement. Globalping tests DNS resolution consistency from distributed locations; the port 25 probe tests SMTP transport reachability and STARTTLS encryption. Different layers, both needed.

### Email Header Analyzer — User Education Enhancement (2026-02-17)

**Problem**: When the "authenticated scam" attack pattern was detected (auth passes, subject has scam indicators), the Big Question logic gap meant users only saw the generic spam question, not the more specific subject-line education. The combined spam + subject scam case was the most dangerous scenario but had the weakest educational response.

**Fixes applied**:

1. **Big Question three-way logic**: Restructured to prioritize combined case (spam + subject + all auth pass) with the strongest educational message: "How did a scam email pass every authentication check?" Falls through to spam-only or subject-only cases correctly.

2. **"Understanding This Attack" educational callout**: New three-step visual card that only appears when subject scam analysis triggers a suspicious verdict. Shows the full attack chain:
   - Step 1: Legitimate Infrastructure (why authentication passes)
   - Step 2: Weaponized Content (how subject lines are crafted with homoglyphs)
   - Step 3: The Trap (what the scammer wants you to do)
   - Key takeaway: authentication verifies identity, not intent

**Lesson learned**: When multiple detection layers fire simultaneously, the educational response should be STRONGER (combined explanation), not weaker (showing only the first match).

---

## Session: February 17, 2026 (v26.19.23) — Documentation Governance & Audit

### replit.md Stability Resolution

**Problem**: replit.md kept being overwritten/truncated by the Replit platform. Comprehensive writes (162+ lines) would revert to a shorter platform-generated default. This happened repeatedly across sessions, wasting significant time on restoration.

**Root cause**: Replit docs confirm replit.md is a platform-managed file designed to be a lightweight agent context that the platform can auto-regenerate. It's NOT intended as a comprehensive knowledge base — it's a config file.

**Solution**: Created `PROJECT_CONTEXT.md` (420 lines) as the stable, canonical project context document. Slimmed replit.md down to ~35 lines (pointer + 10 critical rules + quick reference). If replit.md resets again, there is zero information loss — everything lives in PROJECT_CONTEXT.md and EVOLUTION.md.

**Architecture decision**: replit.md is now a "pointer file" pattern:
- replit.md (~35 lines): Overview + Critical Rules summary + "read PROJECT_CONTEXT.md first"
- PROJECT_CONTEXT.md (~420 lines): Full architecture, stub tables, constraints, roadmap, naming conventions
- EVOLUTION.md: Permanent breadcrumb trail (unchanged role)

### Documentation Audit Findings (v26.19.23)

Full cross-check of public-facing docs (llms.txt, llms-full.txt, FEATURE_INVENTORY.md) against Go implementation.

**Critical fixes applied**:
1. **Posture terminology mismatch**: Docs claimed SECURE/PARTIAL/INSECURE and EXCELLENT/GOOD/MODERATE/WEAK/CRITICAL — neither exists in code. Actual values: Low Risk / Medium Risk / High Risk / Critical Risk (CVSS-aligned). Fixed in all three docs.
2. **TLP:RED omission**: FEATURE_INVENTORY.md listed TLP options but omitted TLP:RED, which IS implemented in the UI. Fixed.
3. **SMTP probe caveat**: FEATURE_INVENTORY.md claimed "live TLS probing" without mentioning that cloud platforms block port 25 and it gracefully skips. Fixed. (llms.txt and llms-full.txt already had the caveat.)
4. **SecurityTrails limits**: Added 50 req/month hard limit and user-key-only caveats to FEATURE_INVENTORY.md.
5. **Version stale**: FEATURE_INVENTORY.md said v26.19.20, actual was v26.19.22. Updated to v26.19.23.

**Loading screen update**: "Posture scoring & remediation" → "Intelligence classification & interpretation" on both results.html and history.html. ICIE is the engine that DOES posture scoring — it's the broader, more accurate label.

### Documentation Files Updated
| File | What Changed |
|------|-------------|
| `PROJECT_CONTEXT.md` | Created (420 lines, all 11 sections) |
| `replit.md` | Slimmed to ~35 lines (pointer pattern) |
| `static/llms.txt` | Posture terminology, SMTP caveat, Email Header Analyzer features |
| `static/llms-full.txt` | Posture terminology (3 locations), SMTP caveat, Email Header Analyzer details |
| `docs/FEATURE_INVENTORY.md` | Version, TLP:RED, SMTP caveat, SecurityTrails limits, Email Header Analyzer |
| `go-server/templates/results.html` | Loading label: "Intelligence classification & interpretation" |
| `go-server/templates/history.html` | Loading label: "Intelligence classification & interpretation" |
| `go-server/internal/config/config.go` | AppVersion 26.19.22 → 26.19.23 |

### Lesson Learned
- **replit.md is volatile by design**. Never put comprehensive context in it. Use it as a pointer to stable files.
- **Audit public-facing docs against actual Go code regularly**. The posture terminology drift (SECURE/PARTIAL/INSECURE vs Low Risk/etc.) was present for multiple versions without being caught.
- **Subagent audits are effective**: Using parallel subagents for doc creation + cross-checking found 8 issues that manual review missed.

---

## Session: February 17, 2026

### Version Bump: 26.19.23 → 26.19.25

### Registrar Subtitle Wording (v26.19.24)
- Changed fallback registrar subtitle from "Where you pay to own domain" → "Where domain was purchased"
- Clearer, more professional wording

### Email Service Provider Enhancement (v26.19.24)
- When intel stub returns "Unknown" for `email_hosting`, orchestrator now falls back to `dkim_analysis.primary_provider` (framework-level detection)
- This populates the Email Service Provider card from MX/SPF/DKIM analysis even in the OSS build
- Added "Inferred" confidence badge with method "MX record and SPF analysis"
- No-mail domains still correctly show "No Mail Domain"
- Safe type assertion for `email_confidence` to prevent panics

### AI Surface Scanner RFC Citations (v26.19.24–25)
- **llms.txt subsection**: Added llmstxt.org "Proposed Standard" link + RFC 8615 (Well-Known URIs)
- **robots.txt subsection**: Added RFC 9309 (Robots Exclusion Protocol) + IETF AIPREF working group draft
- Tooltip descriptions explain each standard's scope and status
- Labels distinguish clearly: "RFC 9309" (ratified), "IETF Draft" (not yet ratified), "Proposed Standard" (community proposal)

### IETF AIPREF vs llmstxt.org — Architect Analysis
- **Not competing**: They solve different problems
  - llms.txt = content guidance ("here's useful info about our site for LLMs to consume at inference time")
  - IETF AIPREF = governance preferences ("here's what you're allowed to do with our content: train-ai=y/n")
- **Complementary**: A domain could have both — llms.txt curates content for LLMs, while AIPREF controls whether AI can train on or use the content
- **Status honestly reported**: RFC 9309 is ratified standard; AIPREF is active IETF working group draft; llms.txt is community proposal with ~844K sites but no confirmed AI vendor support
- **Decision**: Keep both cited with clear status labels. Honesty about standardization status is essential for credibility.

### DMARC Badge Accuracy Fix (v26.19.25)
- **Bug**: When DMARC record exists with p=none but has configuration warnings (status="warning"), the badge showed "No policy published" — misleading because a record IS published
- **Root cause**: Badge logic was gated on `$dmarcStatus == "success"` instead of checking the actual policy value. p=none + warnings → status "warning" → fell through to "No policy published"
- **Fix**: Changed badge logic to key on `$dmarcPolicy` value directly (reject/quarantine/none) instead of `$dmarcStatus`. Now correctly shows "Monitoring only" for p=none regardless of whether there are configuration warnings
- **Impact**: Any domain with DMARC p=none and warnings (common during rollout) was incorrectly showing "No policy published" instead of "Monitoring only"

### Files Changed
| File | What Changed |
|------|-------------|
| `go-server/internal/config/config.go` | AppVersion 26.19.23 → 26.19.25 |
| `go-server/internal/analyzer/orchestrator.go` | Email hosting fallback from DKIM primary_provider |
| `go-server/templates/results.html` | Registrar subtitle, DMARC badge fix, AI Surface Scanner RFC citations |
| `EVOLUTION.md` | Session breadcrumb |

---

## Session: February 17, 2026

### Subdomain Discovery Pipeline Protection (v26.19.30)
- **Context**: Subdomain discovery is now consistently finding subdomains where other tools fail. Was broken for a long time before being fixed. User flagged as the crown jewel of the tool — must be protected.
- **Architect review**: Analyzed full pipeline, identified fragility points (CT single dependency, enrichment ordering, cache/live divergence, in-place mutations).
- **Action**: Added 6 golden rule tests protecting pipeline invariants:
  - `TestGoldenRuleSubdomainCurrentFirstOrdering` — current subdomains always before historical, alphabetical within current, date-descending within historical
  - `TestGoldenRuleDisplayCapNeverHidesCurrent` — display cap never hides active subdomains (120 current + 30 historical → all 120 current + 20 historical shown)
  - `TestGoldenRuleDisplayCapSmallSetUncapped` — sets under 100 never artificially capped
  - `TestGoldenRuleCTUnavailableFallbackProducesResults` — empty CT entries gracefully produce empty results (not errors)
  - `TestGoldenRulePipelineFieldsPreservedThroughSort` — source, first_seen, cname_target, cert_count survive sort
  - `TestGoldenRuleFreeCertAuthorityDetection` — free vs paid CA classification (Let's Encrypt/Amazon/Cloudflare = free; DigiCert/Sectigo = paid)
- **Documentation**: Added "DO NOT BREAK" sections to SKILL.md and PROJECT_CONTEXT.md documenting pipeline sequence, invariants, and do-not-touch zones.
- **Key lesson**: Enrichment (`enrichSubdomainsV2`) MUST happen before sort and count — it mutates `is_current` via live DNS resolution.

### Maintenance Tag Update
- Changed MAINTENANCE_NOTE from "Accuracy Tuning · Feb 18–20" to "Accuracy Tuning · Feb 17–20" (user requested start date of today).

### Probe Server Reconnaissance — dns-observe.com
- **First probe node provisioned**: `probe-us-01.dns-observe.com`
- **SSH access confirmed** from Replit via ed25519 key (secrets: PROBE_SSH_PRIVATE_KEY, PROBE_SSH_HOST, PROBE_SSH_USER, PROBE_API_URL)
- **Server survey**:
  - Ubuntu 24.04.4 LTS, kernel 6.8.0, 2 CPU, 8GB RAM, 96GB disk
  - Caddy reverse proxy: HTTPS → 127.0.0.1:8080 (nothing on 8080 yet — ready for service)
  - DNS tools: dig (BIND 9.18), nslookup, host, curl, wget
  - Security: Monarx agent running, UFW firewall active
  - No Go, no Docker — clean slate
  - IPv6: 2a02:4780:... (European hosting provider, likely Hetzner)
- **Architect-reviewed integration plan**:
  - Lightweight Go HTTP service on port 8080 behind Caddy
  - Endpoints: `/v1/resolve`, `/v1/mx-probe`, `/v1/smtp-probe`
  - Auth: API key in header, rate-limited, input-validated (domain + RR type whitelist)
  - Stateless, no database — results annotated with probe location + timing
  - Graceful fallback: analysis completes if probe unavailable
  - Deployment: SCP binary + systemd service via SSH
  - Multi-node ready: probe registry with health checks
- **Value**: External vantage DNS resolution + SMTP port 25 probing (blocked from cloud platforms). Strengthens subdomain discovery.
- **Naming convention**: `probe-{region}-{number}.dns-observe.com` — designed for expansion.

### Files Changed
| File | What Changed |
|------|-------------|
| `go-server/internal/config/config.go` | AppVersion 26.19.29 → 26.19.30 |
| `go-server/internal/analyzer/golden_rules_test.go` | 6 new pipeline protection tests |
| `.agents/skills/dns-tool/SKILL.md` | Subdomain discovery "DO NOT BREAK" section |
| `PROJECT_CONTEXT.md` | Pipeline critical infrastructure docs, probe network roadmap detail |
| `EVOLUTION.md` | Session breadcrumb |

---

## Session: February 17, 2026

### Accuracy Tuning Window (v26.19.38+)

#### No-Mail Domain Remediation Fix (#4)
- **Bug**: `appendNoMailHardeningFixes()` and `appendProbableNoMailFixes()` were missing `SeverityColor`, `SeverityOrder`, and `RFCURL` fields
- **Impact**: Template renders `bg-{{severity_color}}` — empty string produced `bg-` (invisible) badges. Priority Actions appeared empty for null MX domains even though fixes were generated correctly
- **Fix**: Added `severityHigh`/`colorHigh`/SeverityOrder:1/RFCURL to both SPF and DMARC no-mail fixes
- **Verified**: patientreminder.com now shows visible "High" severity badges for DMARC/SPF fixes

#### DMARC Monitoring Phase Consistency (#9)
- **Bug**: `evaluateDeliberateMonitoring()` required `configuredCount >= 3` (too strict) and didn't detect `p=quarantine` at 100% with rua as a deployment phase
- **Fix**: Lowered threshold to `>= 2` (SPF + DMARC alone is enough). Added quarantine detection path
- **Rationale**: p=quarantine at 100% with rua means the domain is in active deployment phase (hasn't moved to reject yet)

#### No-Mail Domain Classification Tiers (Educational)
- **Change**: Split single `no_mail` classification into three granular tiers:
  1. `no_mail_verified` — Null MX + SPF -all + DMARC reject (fully hardened, green alert)
  2. `no_mail_partial` — Null MX present but missing controls (yellow warning, shows missing steps + recommended records)
  3. `no_mail_intent` — No MX + SPF -all but no Null MX (blue info, educational section)
- **Educational messaging**: `no_mail_intent` template shows "It looks like this is meant to be a no-mail domain" with three numbered RFC standards (7505, 7208, 7489), exact DNS records to copy, and signal status badges
- **Key code**: `classifyMailPosture()` in `remediation.go`, template sections in `results.html`
- **noMailSignalDef**: Added `rfcURL` field so signal badges can link to RFC specs

#### Cross-Browser Test Suite
- Created Playwright configuration with 5 browser targets (Chromium, Firefox, WebKit, iPhone Safari, iPad Safari)
- Test files: homepage smoke, navigation, responsive layout, Safari-specific compat checks
- GitHub Actions CI workflow for matrix tests on push/PR

#### Safari Animation Fix
- Overlay uses opacity/visibility transitions instead of display:none for WebKit animation restart compatibility

### Regression Tests Added
- `TestNoMailRemediationHasSeverityColor` — ensures no-mail fixes always have visible badge colors
- `TestProbableNoMailRemediationHasSeverityColor` — same for probable no-mail fixes
- `TestDeliberateMonitoringNoneWithRua` — p=none + rua triggers monitoring
- `TestDeliberateMonitoringQuarantineFull` — p=quarantine at 100% + rua triggers deployment phase
- `TestDeliberateMonitoringQuarantinePartial` — p=quarantine at 50% + rua triggers deployment phase
- `TestDeliberateMonitoringNoRua` — no rua = no monitoring detection
- `TestDeliberateMonitoringRejectNotMonitoring` — p=reject is NOT monitoring
- `TestMailPostureClassificationNoMailVerified` — null MX + SPF + DMARC reject = verified
- `TestMailPostureClassificationNoMailPartial` — null MX without full controls = partial
- `TestMailPostureClassificationNoMailIntent` — no MX + SPF -all = intent
- `TestMailPostureClassificationProtected` — full mail domain = protected

### SKILL.md Updates
- Clarified two-repo boundary: agent works ONLY in DnsToolWeb, cannot push to remotes
- Added no-mail domain classification documentation with three-tier table

### Files Changed
| File | What Changed |
|------|-------------|
| `go-server/internal/analyzer/remediation.go` | SeverityColor/SeverityOrder/RFCURL for no-mail fixes; three-tier classifyMailPosture; noMailSignalDef rfcURL field |
| `go-server/internal/analyzer/posture.go` | Monitoring threshold 3→2; quarantine deployment phase detection |
| `go-server/templates/results.html` | no_mail_intent educational template section |
| `go-server/internal/analyzer/golden_rules_test.go` | 11 new regression tests |
| `.agents/skills/dns-tool/SKILL.md` | Repo boundary clarification; no-mail classification docs |
| `EVOLUTION.md` | Session breadcrumb |

---

## Session: February 17, 2026 (Part 2)

### Cross-Repo Sync Mechanism Established

- **Discovery**: The GitHub integration (Octokit, `repo` scope) can directly read/write to `careyjames/dnstool-intel` via the GitHub API. Previous sessions (Feb 17 Part 1) used this to push `_intel.go` files — but the mechanism wasn't documented anywhere, causing confusion in subsequent sessions.
- **Script created**: `scripts/github-intel-sync.mjs` — CLI tool for listing, reading, pushing, and deleting files in the Intel repo via the GitHub Contents API. Commands: `list`, `read <path>`, `push <local> <remote> [msg]`, `delete <path> [msg]`, `commits [n]`.
- **Authentication**: Uses Replit's connector API to get a GitHub access token automatically. No separate API key needed — the existing GitHub integration handles it.

### golden_rules_intel_test.go Moved to Private Repo

- **Problem**: `golden_rules_intel_test.go` (229 lines) was sitting in the public DnsToolWeb repo. Although it had `//go:build intel` so it wouldn't compile in OSS builds, the source code was visible — containing enterprise provider pattern tests (AWS, Cloudflare, Azure detection patterns).
- **Action**: Pushed to `careyjames/dnstool-intel` at `go-server/internal/analyzer/golden_rules_intel_test.go` (commit f318696), then deleted from DnsToolWeb working directory.
- **Verification**: `go test ./go-server/... -count=1` passes — all tests still green without the intel test file.

### Public Repo Audit — Clean

- No `_intel.go` files remain in DnsToolWeb
- All `_oss.go` stubs properly tagged `//go:build !intel`
- Today's changes (remediation.go, posture.go, results.html) are framework-only — no proprietary provider databases or intelligence patterns

### SKILL.md Updated

- Replaced "NOT accessible from this environment" with proper cross-repo sync documentation
- Added `scripts/github-intel-sync.mjs` usage reference
- Added CRITICAL rule: always push `_intel.go` to Intel repo and delete from local before committing

### Key Lesson

The two-repo architecture works when the sync mechanism is documented. Without documentation, each new session assumes it can't access the Intel repo and may recreate intel files locally (in the public repo). The sync script and SKILL.md documentation prevent this.

### Files Changed
| File | What Changed |
|------|-------------|
| `scripts/github-intel-sync.mjs` | NEW — GitHub API helper for Intel repo read/write/push/delete |
| `go-server/internal/analyzer/golden_rules_intel_test.go` | DELETED from DnsToolWeb (moved to Intel repo) |
| `.agents/skills/dns-tool/SKILL.md` | Cross-repo sync documentation; sync script usage |
| `EVOLUTION.md` | Session breadcrumb |
