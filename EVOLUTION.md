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
