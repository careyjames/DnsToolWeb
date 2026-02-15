# DNS Tool — Evolution Log

This file is the persistent record of all significant decisions, changes, and rationale across development sessions. It serves as a backup for `replit.md` (which may be reset by the platform) and as the canonical history of the project's evolution.

**Rule for the AI agent**: At the start of every session, read this file AND `replit.md`. At the end of every session, append new entries here. If `replit.md` has been reset/truncated, restore its content from this file.

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
- Reason: The server-side SecurityTrails API key has a hard 50-request/month limit. Using it automatically on every scan would exhaust the budget within hours. Once exhausted, the key is dead for the rest of the month — no DNS history, no IP investigation, nothing.
- Correct pattern: SecurityTrails is user-key-only. Users provide their own API key on DNS History and IP Investigation pages. The server key is reserved for features where users explicitly opt in.
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
- Promotional banner added to homepage (`index.html`) below IP Investigate card
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

## Failures & Lessons Learned Timeline

This section tracks recurring issues and failed approaches so future sessions avoid repeating them. **Always read this before starting work.**

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

## Failures & Lessons Learned Timeline

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
