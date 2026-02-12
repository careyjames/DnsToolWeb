# DNS Tool — Feature Inventory

**Version:** 26.12.23
**Last Updated:** February 12, 2026
**Implementation:** Go/Gin (`go-server/`)

---

## Purpose

This document is the authoritative inventory of every analysis feature,
detection capability, and platform function in the DNS Tool. It exists to
protect institutional knowledge—if a feature is listed here, it must be
present in the codebase. Any removal requires a deliberate decision
documented with rationale.

---

## 1. Core DNS Security Analysis

These are the primary analysis modules. Each performs RFC-compliant
parsing and validation of a specific DNS protocol.

| # | Feature | RFC | Source File | Schema Key |
|---|---------|-----|-------------|------------|
| 1 | **SPF Analysis** | RFC 7208 | `spf.go` | `spf_analysis` |
| 2 | **DMARC Analysis** | RFC 7489 | `dmarc.go` | `dmarc_analysis` |
| 3 | **DKIM Analysis** | RFC 6376 | `dkim.go` | `dkim_analysis` |
| 4 | **MTA-STS Analysis** | RFC 8461 | `mta_sts.go` | `mta_sts_analysis` |
| 5 | **TLS-RPT Analysis** | RFC 8460 | `tlsrpt.go` | `tlsrpt_analysis` |
| 6 | **BIMI Analysis** | RFC 9495 | `bimi.go` | `bimi_analysis` |
| 7 | **DANE/TLSA Analysis** | RFC 7671 | `dane.go` | `dane_analysis` |
| 8 | **DNSSEC Analysis** | RFC 4035 | `dnssec.go` | `dnssec_analysis` |
| 9 | **CAA Analysis** | RFC 8659 | `caa.go` | `caa_analysis` |
| 10 | **NS Delegation Analysis** | RFC 1034 | `ns_delegation.go` | `ns_delegation_analysis` |
| 11 | **SMTP Transport Analysis** | RFC 3207 | `smtp_transport.go` | `smtp_transport` |

### 1.1 SPF Analysis (`spf.go`)
- TXT record lookup and SPF record identification
- Mechanism parsing: `include`, `a`, `mx`, `ptr`, `exists`, `redirect`, `ip4`, `ip6`
- DNS lookup counting (10-lookup limit per RFC 7208)
- Include chain resolution
- Permissiveness evaluation (`+all`, `~all`, `-all`, `?all`)
- No-mail intent detection (`v=spf1 -all`)
- Multiple SPF record detection (invalid per RFC)
- SPF-like but invalid record detection

### 1.2 DMARC Analysis (`dmarc.go`)
- `_dmarc` TXT record lookup
- Policy parsing (`p=none/quarantine/reject`)
- Subdomain policy extraction (`sp=`)
- Non-existent domain policy (`np=`)
- Percentage enforcement (`pct=`)
- Alignment modes (`aspf=`, `adkim=` — relaxed/strict)
- Reporting address extraction (`rua=`, `ruf=`)
- Testing mode detection (`t=y`)
- DMARC-like but invalid record detection
- Multiple DMARC record detection
- DMARCbis readiness checks (upcoming standard changes)

### 1.3 DKIM Analysis (`dkim.go`)
- Common selector probing (35 default selectors)
- Provider-specific selector detection
- Key record parsing (`v`, `k`, `p`, `t` flags)
- Key type identification (RSA, Ed25519)
- Key bit length extraction and strength assessment
- Test mode detection (`t=y`)
- Revoked key detection (empty `p=`)
- Provider-aware DKIM credit (known hosted providers)
- Primary mail provider detection from MX/SPF
- Gateway provider detection

### 1.4 MTA-STS Analysis (`mta_sts.go`)
- `_mta-sts` TXT record lookup
- DNS record ID extraction
- Policy file HTTPS fetch (`/.well-known/mta-sts.txt`)
- STSv1 version validation
- Mode parsing (`enforce`, `testing`, `none`)
- Max age validation
- MX list extraction from policy
- Hosting CNAME detection

### 1.5 TLS-RPT Analysis (`tlsrpt.go`)
- `_smtp._tls` TXT record lookup
- TLSRPTv1 version validation
- Reporting address extraction (`rua=` — mailto and https)

### 1.6 BIMI Analysis (`bimi.go`)
- `default._bimi` TXT record lookup
- Logo URL extraction and format validation
- VMC (Verified Mark Certificate) URL extraction
- Logo accessibility check
- VMC certificate parsing (issuer, subject)
- SVG format verification

### 1.7 DANE/TLSA Analysis (`dane.go`)
- `_25._tcp.<mx>` TLSA record lookup per MX host
- Certificate usage parsing (PKIX-TA, PKIX-EE, DANE-TA, DANE-EE)
- Selector type validation (full certificate vs. public key)
- Matching type validation (exact, SHA-256, SHA-512)
- MX provider DANE capability detection (known provider database)
- DNSSEC requirement verification
- Inbound vs. outbound DANE assessment
- Per-host TLSA result aggregation

### 1.8 DNSSEC Analysis (`dnssec.go`)
- DNSKEY record lookup
- DS record lookup (parent zone)
- AD (Authenticated Data) flag validation
- Chain of trust verification
- Key algorithm identification
- DNSSEC-signed zone detection

### 1.9 CAA Analysis (`caa.go`)
- CAA record lookup
- `issue` tag parsing (authorized CAs)
- `issuewild` tag parsing (wildcard certificate CAs, separate per RFC 8659 §4.3)
- `iodef` notification endpoint parsing
- Unrestricted CA detection (no CAA records)
- MPIC (Multi-Perspective Issuance Corroboration) awareness — CA/B Forum Ballot SC-067, mandatory since September 2025

### 1.10 NS Delegation Analysis (`ns_delegation.go`)
- Child zone NS record query
- Parent zone NS delegation query
- Delegation consistency comparison
- Extra/missing NS detection
- Lame delegation detection
- Undelegated domain handling

### 1.11 SMTP Transport Analysis (`smtp_transport.go`)
- Direct SMTP probe (port 25) with STARTTLS negotiation
- TLS version detection (TLS 1.0 / 1.1 / 1.2 / 1.3)
- Cipher suite extraction and strength assessment
- Server certificate validation (issuer, expiry, chain)
- DNS-inferred fallback when port 25 is blocked:
  - MTA-STS enforce mode detection
  - DANE/TLSA record presence
  - TLS-RPT configuration as encryption signal
  - Known provider capability inference (Google, Microsoft, Proton, etc.)
- Explicit labeling of probe mode (direct vs. DNS-inferred) for honesty
- Per-MX-host transport result aggregation
- Summary verdict: Encrypted / Partial / Unencrypted / Inferred

---

## 2. Infrastructure Analysis

| # | Feature | Source File | Schema Key |
|---|---------|-------------|------------|
| 12 | **Basic DNS Records** | `records.go` | `basic_records` |
| 13 | **Authoritative Records** | `records.go` | `authoritative_records` |
| 14 | **Resolver Consensus** | `records.go` | `resolver_consensus` |
| 15 | **Propagation Status** | `records.go` | `propagation_status` |
| 16 | **Registrar/RDAP Lookup** | `registrar.go` | `registrar_info` |
| 17 | **CT Subdomain Discovery** | `subdomains.go` | `ct_subdomains` |
| 18 | **DNS Infrastructure Detection** | `infrastructure.go` | `dns_infrastructure` |
| 19 | **Hosting Summary** | `infrastructure.go` | `hosting_summary` |
| 20 | **Domain Existence Detection** | `orchestrator.go` | `domain_exists` |
| 21 | **Domain Status** | `orchestrator.go` | `domain_status`, `domain_status_message` |
| 22 | **DNS History Timeline** | `dns_history.go` | `dns_history` |

### 2.1 Basic DNS Records (`records.go`)
- Multi-type DNS query: A, AAAA, MX, TXT, NS, CNAME, CAA, SOA, SRV
- TTL extraction per record type
- Record count per type

### 2.2 Authoritative Records (`records.go`)
- Authoritative nameserver discovery
- Direct authoritative query (bypassing resolvers)
- TCP fallback for truncated responses
- Ground-truth record comparison

### 2.3 Resolver Consensus (`records.go`)
- Cloudflare DNS (1.1.1.1) query
- Google Public DNS (8.8.8.8) query
- Quad9 (9.9.9.9) query
- OpenDNS/Cisco Umbrella (208.67.222.222) query
- Cross-resolver result comparison
- Consensus agreement detection

### 2.4 Propagation Status (`records.go`)
- Per-record-type comparison (resolver vs. authoritative)
- Propagation sync detection
- Stale record identification

### 2.5 Registrar/RDAP Lookup (`registrar.go`)
- IANA RDAP bootstrap (1,196 TLDs loaded)
- RDAP HTTP query with caching (24h TTL per RFC 9224)
- Registrar name extraction
- Registrant organization extraction
- Domain creation/expiration date extraction
- NS-based registrar inference (fallback)
- WHOIS server identification

### 2.6 CT Subdomain Discovery (`subdomains.go`)
- crt.sh API query (Certificate Transparency logs, RFC 6962)
- Certificate parsing and deduplication
- Current vs. expired certificate classification
- CNAME resolution for discovered subdomains
- Provider summary from CNAME targets
- 25-second timeout with graceful degradation
- Result caching (1 hour TTL)

### 2.7 DNS Infrastructure Detection (`infrastructure.go`)
- NS hostname matching against known provider database
- Provider tier classification (enterprise / professional / standard / basic)
- Feature detection (DNSSEC support, DDoS protection, anycast, geo-routing)
- Government domain detection (.gov, .mil, .gov.uk, .gov.au, .gc.ca)
- 200+ CNAME-to-provider mappings

### 2.8 Hosting Summary (`infrastructure.go`)
- Web hosting provider detection (A/AAAA IP mapping)
- DNS hosting provider detection (NS records)
- Email hosting provider detection (MX records)
- IP-to-country lookup (ip-api.com)

### 2.9 Domain Existence & Status (`orchestrator.go`)
- NXDOMAIN detection
- SERVFAIL detection
- Undelegated domain handling
- Human-readable status messages (`domain_status_message`)

### 2.10 DNS History Timeline (`dns_history.go`)
- SecurityTrails API integration for historical A, MX, NS records
- Change event extraction (added/removed records with dates)
- Organization attribution per IP/hostname
- Dedicated 24h TTL cache (isolated from live analysis cache)
- Only caches successful responses — never caches rate-limited or error states
- Four-state honest status reporting: success, rate_limited, error, partial
- Template messaging matches status — no false "no changes" claims when data is unavailable
- SecurityTrails limitations: 50 API queries/month (~16 unique domain scans at 3 calls per scan)
- No alternative free DNS history API exists with equivalent data quality; tool is transparent about this limitation

---

## 3. Assessment & Scoring

| # | Feature | Source File | Schema Key |
|---|---------|-------------|------------|
| 23 | **Security Posture Assessment** | `posture.go` | `posture` |
| 24 | **Mail Posture Classification** | `posture.go` | `mail_posture` |
| 25 | **Remediation Engine** | `remediation.go` | `remediation` |

### 3.1 Security Posture Assessment (`posture.go`)
- CVSS-aligned risk levels: Informational → Low → Medium → High → Critical
- Protocol state evaluation (SPF + DMARC + DKIM + CAA presence)
- DMARC policy strength assessment (none / quarantine / reject)
- Partial `pct` enforcement detection
- Missing reporting (`rua`) warning
- Provider-aware DKIM credit (known hosted providers)
- Deliberate monitoring detection (`p=none` with `rua`)
- No-mail domain recognition
- Per-category posture breakdown

### 3.2 Mail Posture Classification (`posture.go`)
- Mail intent classification: `email_enabled`, `no_mail_verified`, `no_mail_partial`, `likely_no_mail`
- MX record presence/absence analysis
- Null MX detection (RFC 7505)
- SPF `-all` / `v=spf1 -all` detection
- Signal aggregation (MX, SPF, DMARC, DKIM, MTA-STS presence)

### 3.3 Remediation Engine (`remediation.go`)
- Per-section status evaluation
- Severity classification: Critical / High / Medium / Low
- DNS record examples with actual domain (copy-paste ready)
- RFC section references with citations
- Top 3 priority fixes sorted by severity
- Achievable posture projection ("if you fix these, you reach X")
- Category-specific guidance

---

## 4. Detection & Intelligence

| # | Feature | Source File | Schema Key |
|---|---------|-------------|------------|
| 26 | **Email Security Management Detection** | `infrastructure.go` | `email_security_mgmt` |
| 27 | **Null MX Detection** | `posture.go` | `has_null_mx` |
| 28 | **No-Mail Domain Detection** | `posture.go` | `is_no_mail_domain` |

### 4.1 Email Security Management Detection (`infrastructure.go`)
- DMARC `rua` URI provider matching (30+ monitoring providers)
- DMARC `ruf` URI provider matching
- TLS-RPT `rua` URI provider matching
- SPF include flattening provider detection (15+ providers)
- Hosted DKIM CNAME chain detection
- MTA-STS CNAME hosting detection
- Dynamic services NS delegation detection (_dmarc, _domainkey, _mta-sts, _smtp._tls subzones)
- CNAME provider mapping (200+ mappings)

---

## 5. Data & Metadata

| # | Feature | Source File | Schema Key |
|---|---------|-------------|------------|
| 29 | **Data Freshness Tracking** | `orchestrator.go` | `_data_freshness` |
| 30 | **Section Status Summary** | `orchestrator.go` | `section_status` |
| 31 | **Authoritative Query Status** | `records.go` | `auth_query_status` |
| 32 | **Resolver TTL** | `records.go` | `resolver_ttl` |
| 33 | **Authoritative TTL** | `records.go` | `auth_ttl` |

---

## 6. Platform Features

| # | Feature | Handler | Template |
|---|---------|---------|----------|
| 34 | **Domain Analysis** | `analysis.go` | `results.html` |
| 35 | **Analysis History** | `history.go` | `history.html` |
| 36 | **Domain Comparison** | `compare.go` | `compare.html` |
| 37 | **Statistics Dashboard** | `stats.go` | `stats.html` |
| 38 | **JSON Export** | `export.go` | — |
| 39 | **BIMI Logo Proxy** | `proxy.go` | — |
| 40 | **Health Check** | `health.go` | — |
| 41 | **PWA / Service Worker** | `static.go` | `sw.js` |

### 6.1 Domain Analysis
- Single-domain comprehensive audit
- Re-analyze capability
- Partial results handling (timeouts, failures)
- Copy-to-clipboard for DNS records
- Section collapse/expand
- Executive print/PDF report (see §6.1.1)

#### 6.1.1 Print/PDF Report
Professional, client-facing print layout designed for executive audiences.
- **TLP classification**: TLP:CLEAR badge per FIRST.org Traffic Light Protocol (DNS records are public data)
- **Domain banner**: Full-width navy banner with domain name as the visual focal point (22pt monospace, centered)
- **Branded header**: Gradient accent bar (navy→teal→amber), company logo, report title, generation metadata
- **Section headers**: Major sections (Email Security, Brand Security, Domain Security, Traffic & Routing) use colored solid backgrounds (navy/teal alternating) with white text for visual rhythm
- **Posture cards**: Colored left-border accents (green/amber/red/teal) indicating risk severity
- **Code blocks**: Teal left-accent bar for DNS record display
- **Tables**: Navy header rows with white text, zebra-striped body rows
- **Badges**: Solid colors mapped to distinct grayscale values for B&W laser printer safety (green=#166534, teal=#0e7490, amber=#d97706, red=#991b1b)
- **Alerts**: Left-border accent style with semantic coloring
- **RFC links**: Teal pill badges
- **Page breaks**: Controlled pagination between major sections
- **Footer**: Matching gradient accent bar, three-column layout (company, tagline, contact), TLP disclaimer
- **B&W safe**: All colors chosen for distinct grayscale mapping — report remains fully legible on monochrome laser printers
- **Source**: `static/css/custom.css` (@media print), `go-server/templates/results.html` (print-only markup)

### 6.2 Analysis History
- Paginated history with search
- Per-analysis email security badge summary (SPF/DMARC/DKIM status)
- View, re-analyze, compare actions per entry
- Duration tracking

### 6.3 Domain Comparison
- Side-by-side comparison of two analysis results
- Historical result selection
- Posture score comparison

### 6.4 Statistics Dashboard
- Aggregate analysis statistics
- Protocol adoption rates
- Common provider distributions

### 6.5 JSON Export
- Full analysis results as downloadable JSON
- Structured for programmatic consumption

---

## 7. Security & Infrastructure

| # | Feature | Source |
|---|---------|-------|
| 42 | **CSRF Protection** | `middleware/csrf.go` — HMAC-signed cookie tokens |
| 43 | **Rate Limiting** | `middleware/rate_limit.go` — 8 req/min per IP |
| 44 | **SSRF Hardening** | `dnsclient/` — private IP blocking |
| 45 | **Multi-Resolver DNS Client** | `dnsclient/` — TCP with DoH fallback |
| 46 | **Provider Health Telemetry** | `telemetry/` — resolver latency tracking |
| 47 | **RDAP Response Caching** | `telemetry/` — 24h TTL per RFC 9224 |
| 48 | **DNS History Caching** | `dns_history.go` — 24h TTL, isolated from analysis cache |
| 49 | **Concurrent Orchestrator** | `orchestrator.go` — goroutine-based parallel analysis |
| 50 | **60s Master Deadline** | `orchestrator.go` — context-based timeout |

---

## 8. Provider Databases

| Database | Location | Count |
|----------|----------|-------|
| CNAME Provider Map | `providers.go` | 178 mappings |
| DANE MX Capability | `providers.go` | Known DANE-capable mail providers |
| DMARC Monitoring Providers | `providers.go` | 173 provider patterns |
| SPF Flattening Providers | `providers.go` | 15+ providers |
| Hosted DKIM Providers | `providers.go` | Known hosted DKIM services |
| Dynamic Services Zones | `providers.go` | DNS delegation subzone patterns |
| DNS Infrastructure Providers | `infrastructure.go` | Enterprise/professional/standard tiers |
| DKIM Selector Database | `dkim.go` | 35 default selectors |
| IANA RDAP Bootstrap | Runtime loaded | 1,196 TLDs |

---

## Total Feature Count: 50

**Analysis Modules:** 11 | **Infrastructure:** 11 | **Assessment:** 3 |
**Detection:** 3 | **Metadata:** 5 | **Platform:** 8 | **Security:** 9

---

## Automated Feature Parity Verification

Feature parity is enforced by an automated Go test suite that runs on every
build. The living manifest lives at:

    go-server/internal/analyzer/manifest.go     — the source of truth
    go-server/internal/analyzer/manifest_test.go — automated enforcement

The tests verify:
- Every schema key in the manifest is present in actual orchestrator output
- No duplicate schema keys exist
- Every entry has required fields (Feature, Category, SchemaKey, DetectionMethods)
- Minimum feature counts per category are maintained
- The manifest never drops below 33 features (the original migration baseline)

**If you add a new feature**, add its entry to `FeatureParityManifest` in
`manifest.go`. The tests will catch it if you forget.

**If you remove a feature**, remove its entry from the manifest with
documented rationale. The tests will fail until both the manifest and the
orchestrator are in sync.

The legacy Python manifest (`docs/legacy/tests/feature_parity_manifest.py`)
is archived for historical reference. The Go manifest supersedes it.

### Current Status: All 33 of 33 schema keys verified.

| Manifest Schema Key | Go Source | Status |
|---------------------|-----------|--------|
| `spf_analysis` | `analyzer/spf.go` | Implemented |
| `dmarc_analysis` | `analyzer/dmarc.go` | Implemented |
| `dkim_analysis` | `analyzer/dkim.go` | Implemented |
| `mta_sts_analysis` | `analyzer/mta_sts.go` | Implemented |
| `tlsrpt_analysis` | `analyzer/tlsrpt.go` | Implemented |
| `bimi_analysis` | `analyzer/bimi.go` | Implemented |
| `dane_analysis` | `analyzer/dane.go` | Implemented |
| `dnssec_analysis` | `analyzer/dnssec.go` | Implemented |
| `caa_analysis` | `analyzer/caa.go` | Implemented |
| `ns_delegation_analysis` | `analyzer/ns_delegation.go` | Implemented |
| `basic_records` | `analyzer/records.go` | Implemented |
| `authoritative_records` | `analyzer/records.go` | Implemented |
| `resolver_consensus` | `analyzer/records.go` | Implemented |
| `propagation_status` | `analyzer/records.go` | Implemented |
| `registrar_info` | `analyzer/registrar.go` | Implemented |
| `ct_subdomains` | `analyzer/subdomains.go` | Implemented |
| `dns_infrastructure` | `analyzer/infrastructure.go` | Implemented |
| `hosting_summary` | `analyzer/infrastructure.go` | Implemented |
| `email_security_mgmt` | `analyzer/infrastructure.go` | Implemented |
| `mail_posture` | `analyzer/posture.go` | Implemented |
| `posture` | `analyzer/posture.go` | Implemented |
| `remediation` | `analyzer/remediation.go` | Implemented |
| `_data_freshness` | `handlers/helpers.go` | Implemented |
| `domain_exists` | `analyzer/orchestrator.go` | Implemented |
| `domain_status` | `analyzer/orchestrator.go` | Implemented |
| `domain_status_message` | `analyzer/orchestrator.go` | Implemented |
| `section_status` | `analyzer/orchestrator.go` | Implemented |
| `auth_query_status` | `analyzer/records.go` | Implemented |
| `resolver_ttl` | `analyzer/records.go` | Implemented |
| `auth_ttl` | `analyzer/records.go` | Implemented |
| `smtp_transport` | `analyzer/smtp_transport.go` | Implemented |
| `has_null_mx` | `analyzer/posture.go` | Implemented |
| `is_no_mail_domain` | `analyzer/posture.go` | Implemented |

The remaining 15 features in this inventory (items 33–48) are platform,
security, and infrastructure capabilities that exist beyond the analysis
schema — they are handlers, middleware, and runtime components not tracked
by the legacy parity manifest.
