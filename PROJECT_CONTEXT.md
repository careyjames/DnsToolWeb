# DNS Tool — Project Context (Canonical)

> **This is the canonical project context document. Unlike `replit.md` (which the Replit platform may overwrite), this file is stable and persistent. If `replit.md` resets, restore key pointers from this file and `EVOLUTION.md`.**

---

## 1. Overview

The DNS Tool is an OSINT platform for comprehensive, RFC-compliant domain security analysis. It uses publicly available intelligence (DNS records, certificate transparency logs, RDAP data, web resources) to provide immediate, verifiable domain state information.

Key capabilities include auditing critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), automatic subdomain discovery, DNS history timelines, an AI Surface Scanner, IP Intelligence, an Email Header Analyzer (with subject line scam detection, third-party spam vendor integration, and homoglyph analysis), and posture drift detection foundation.

The project aims for an open-source model while protecting commercial viability, targeting both technical sysadmins and non-technical executives.

Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."

Every conclusion must be independently verifiable using standard commands. The tool operates with strict adherence to RFC standards and observation-based language — never making definitive claims beyond what the data shows.

---

## 2. User Preferences

- Preferred communication style: Simple, everyday language.
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets technical sysadmins, non-technical executives (board-level), and the InfoSec/security research community (red teams, pen testers, bug bounty hunters).
- Memory persistence is critical — `replit.md` is the quick-reference config between sessions. Update it every session with decisions, changes, and rationale.
- **IMPORTANT**: If `replit.md` appears truncated or reset, restore from `EVOLUTION.md` which is the persistent backup. Always read BOTH files at session start.
- **CRITICAL**: Read the "Failures & Lessons Learned — Detailed Analysis" section in `EVOLUTION.md` before making any changes. It documents recurring mistakes (CSP inline handlers, font subset issues, PDF title format, print readability) with correct solutions.
- **MANDATORY POST-EDIT RULE**: After ANY Go code changes, run `go test ./go-server/... -count=1` before considering the work done. This runs the boundary integrity tests that catch intelligence leaks, stub contract breakage, duplicate symbols, and architecture violations. Regressions cost $100-200/day — never skip this step.
- **REALITY CHECK RULE (v26.19.20)**: Every homepage claim, schema statement, and documentation assertion must be backed by implemented code. Do NOT claim features that are stubs or planned. Use language like "on the roadmap" for future items, "context" instead of "verification" for informational features (e.g., MPIC).
- **BREADCRUMBS**: `EVOLUTION.md` is the project's permanent breadcrumb trail — every session's decisions, changes, lessons, and rationale. `replit.md` is the quick-reference config. Both must be updated every session. If `replit.md` resets, restore from `EVOLUTION.md`.

---

## 3. System Architecture

### Core System

The application is built in Go using the Gin framework, emphasizing performance and concurrency, following an MVC-style separation. The build process uses `./build.sh` which compiles to `./dns-tool-server`, and `main.py` acts as a gunicorn trampoline to launch the Go binary (via `os.execvp`). All Go and CSS changes require rebuilding and restarting the workflow.

```
main.py                    # Process trampoline (execs Go binary)
dns-tool-server            # Compiled Go binary
go-server/
  cmd/server/main.go       # Entry point
  internal/
    analyzer/              # DNS analysis engine
    handlers/              # HTTP route handlers
    dnsclient/             # Multi-resolver DNS client
    config/                # Configuration (version, maintenance tags)
    db/                    # PostgreSQL (pgx v5, sqlc)
    dbq/                   # sqlc-generated query code
    middleware/            # Security middleware (CSRF, rate limiting)
    models/                # Data models
    providers/             # Provider detection
    telemetry/             # Caching, metrics
    templates/             # Template helper functions
  templates/               # Server-rendered HTML (Go html/template)
  scripts/                 # Utility scripts (audit_icons.py)
  db/                      # Schema and query definitions
    schema/                # schema.sql
    queries/               # SQL query files for sqlc
static/                    # CSS, JS, fonts, images
stubs/                     # Stub reference copies for contract tests
templates/                 # Python Flask templates (legacy/trampoline)
```

### Backend

The backend utilizes Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` v2 (`codeberg.org/miekg/dns` v0.6.52) for DNS queries. Key implemented features:

- Multi-resolver DNS client with DoH fallback and high-speed UDP probing
- Multi-layer subdomain discovery (proprietary pipeline — see intel repo for implementation details)
- Posture scoring with CVSS-aligned risk levels
- Concurrent orchestrator with independent contexts per task
- Mail Transport Security (three-tier: policy/telemetry/probe, RFC 8461/7672 aligned)
- CSRF middleware, rate limiting, SSRF hardening, telemetry
- DMARC external reporting authorization, dangling DNS/subdomain takeover detection
- HTTPS/SVCB intelligence, IP-to-ASN attribution (Team Cymru), Edge/CDN vs origin detection
- SaaS TXT footprint extraction, CDS/CDNSKEY, SMIMEA/OPENPGPKEY, security.txt detection
- AI Surface Scanner (llms.txt, AI crawler governance, prefilled prompts, CSS-hidden prompt injection)
- SPF redirect chain handling with loop detection, SPF provider detection with MX corroboration
- DKIM gateway inference pipeline (detects mailbox provider behind security gateways)
- DNS history timeline, IP Intelligence page
- OpenPhish phishing URL feed integration
- Email Header Analyzer: SPF/DKIM/DMARC verification, multi-format (.eml/.json/.mbox/.txt), third-party spam vendor detection (Proofpoint/Barracuda/Microsoft SCL/Mimecast), subject line scam analysis (phone numbers/payment amounts/homoglyphs/scam phrases), brand mismatch with homoglyph normalization, BCC detection, educational "Understanding This Attack" callout
- Public exposure checks, expanded exposure checks (opt-in)
- Report integrity hash (SHA-256), posture hash for drift detection
- Enterprise DNS Detection, Analysis Integrity Standard, Remediation Engine ("Priority Actions")
- ICIE (Intelligence Classification and Interpretation Engine)
- Per-section maintenance tags system
- BSL 1.1 license for both public and private repositories

### Frontend

Server-rendered HTML with Go html/template, Bootstrap dark theme, custom CSS, client-side JavaScript. PWA, accessibility, mobile responsive. Dual intelligence products: Engineer's DNS Intelligence Report (technical) and Executive's DNS Intelligence Brief (board-ready), both with configurable FIRST TLP v2.0 (default: TLP:AMBER). Plain-language questions with data-driven badge answers. Big Questions for critical thinking.

### Privacy Controls for User-Provided Intelligence (v26.20.71)

Three analysis modes protect user-submitted DKIM selectors:
- **Public**: No custom selectors, or only known/default selectors (google, selector1, selector2, etc.) — saves to history, viewable by anyone.
- **Private**: Authenticated user + genuinely novel selectors — saved with `private=true`, visible only to the owner in their Intelligence Reports. Returns 404 to unauthenticated users, 403 with informative message to authenticated non-owners.
- **Ephemeral**: Anonymous user + genuinely novel selectors — analysis runs and displays results, but nothing is persisted to database. Banner explains results won't be saved.

Known-selector bypass: `analyzer.AllSelectorsKnown()` compares user input against `defaultDKIMSelectors` (case-insensitive, whitespace-trimmed). Entering publicly known selectors like `google`, `selector1`, `selector2` does NOT trigger privacy mode.

DB columns: `domain_analyses.private` (BOOLEAN), `domain_analyses.has_user_selectors` (BOOLEAN). All public history queries filter `private = FALSE`.

Intelligence Reports page: `/dossier` (renamed from "Intelligence Dossier" to "Intelligence Reports" in v26.20.70).

---

## 4. External Dependencies

### External Services

| Service | Purpose | Constraints |
|---------|---------|-------------|
| **DNS Resolvers** (Cloudflare, Google, Quad9, OpenDNS/Cisco Umbrella) | Multi-resolver consensus DNS queries | Public, no API key |
| **IANA RDAP** | Registry data lookups | Multi-endpoint, parallel attempts, exponential backoff |
| **ip-api.com** | Visitor IP-to-country lookups | Public tier |
| **crt.sh** | Certificate Transparency logs | Independent context with timeout and size limits |
| **SecurityTrails** | DNS history and IP Intelligence | **⚠️ 50 req/month HARD LIMIT. User-provided API key ONLY. NEVER call automatically.** |
| **Team Cymru** | DNS-based IP-to-ASN attribution | Independent 8s context |
| **OpenPhish** | Phishing URL feed (Email Header Analyzer body scanning) | Community feed |

**CRITICAL SecurityTrails Rule**: SecurityTrails has a server-side API key with a hard 50-request/month limit. Using it automatically on every scan would exhaust the budget within hours. Once exhausted, the key is dead for the rest of the month — no DNS history, no IP Intelligence, nothing. Correct pattern: Users provide their own API key on DNS History and IP Intelligence pages. The server key is reserved for features where users explicitly opt in. **Never call SecurityTrails automatically in the analysis pipeline.**

### Database

- **PostgreSQL**: Immutable, append-only analysis data with `posture_hash` and `integrity_hash` columns
- Development and production use separate databases (platform change, Dec 2025)

### Caching Strategy

| Cache Target | TTL | Reason |
|--------------|-----|--------|
| DNS queries | TTL=0 (none) | Live data for security incidents |
| RDAP data | 24h | Registrar info rarely changes |
| DNS History | 24h | SecurityTrails API quota protection (50 calls/month) |
| CT subdomains | 1h | Append-only historical data |
| RFC metadata | 24h | Reference data, infrequent updates |

---

## 5. Two-Repo Build-Tag Architecture

Two-repository design with Go build tags (`//go:build intel` / `//go:build !intel`):
- **DNS Tool Web** (public, `careyjames/DnsToolWeb`): Full framework + `_oss.go` stubs (empty maps, safe defaults)
- **dnstool-intel** (private, `careyjames/dnstool-intel`): `_intel.go` files with proprietary provider databases

### Intel Repo Access from Replit

The Replit GitHub integration (Octokit, full `repo` scope) provides direct read/write access to `careyjames/dnstool-intel` via the GitHub Contents API. A sync script handles all operations:

```bash
node scripts/github-intel-sync.mjs list                              # List all Intel repo files
node scripts/github-intel-sync.mjs read <path>                       # Read a file
node scripts/github-intel-sync.mjs push <local> <remote> [message]   # Push local file
node scripts/github-intel-sync.mjs delete <path> [message]           # Delete file
node scripts/github-intel-sync.mjs commits [count]                   # Show recent commits
```

**MANDATORY WORKFLOW for `_intel.go` files**:
1. Write the `_intel.go` file locally (for testing/development)
2. Push it to `dnstool-intel` via: `node scripts/github-intel-sync.mjs push <local-path> <remote-path> "commit message"`
3. DELETE the local file immediately — do not leave it in DnsToolWeb
4. Verify: `find go-server -name "*_intel*"` should return nothing

**WHY**: Even with `//go:build intel` tags, source code committed to DnsToolWeb is visible in the public Git history. Build tags only affect compilation, not visibility. Proprietary provider databases, detection patterns, and intelligence test cases must NEVER exist in the public repo — not even temporarily.

### Git Operations — GitHub API (NOT Git CLI)

**The Replit shell blocks `git` CLI commands** ("Avoid changing .git repository" error). This does NOT mean you can't do Git operations. The GitHub integration (Octokit, `@octokit/rest`, full `repo` scope) gives complete read/write access to BOTH repos (`careyjames/DnsToolWeb` and `careyjames/dnstool-intel`).

**Use the GitHub API for**:
- Pushing changes to DnsToolWeb when the Replit Git panel fails (PUSH_REJECTED, diverged branches)
- Pushing `_intel.go` files to dnstool-intel (via `scripts/github-intel-sync.mjs`)
- Deleting files from either remote repo
- Reading files from dnstool-intel to check current Intel repo state
- Resolving branch divergence without force-push (create commit on top of remote HEAD)

**GitHub API push pattern** (for DnsToolWeb when the Git panel can't sync):
1. Get remote HEAD: `octokit.git.getRef({ owner, repo, ref: 'heads/main' })`
2. Get base tree: `octokit.git.getCommit({ commit_sha: headSha })`
3. Create blobs for changed files: `octokit.git.createBlob({ content, encoding: 'base64' })`
4. Create new tree: `octokit.git.createTree({ base_tree: baseTreeSha, tree: entries })`
5. Create commit: `octokit.git.createCommit({ tree: newTreeSha, parents: [remoteHeadSha], message })`
6. Update ref: `octokit.git.updateRef({ ref: 'heads/main', sha: newCommitSha })`

To delete a file, include it in the tree entries with `sha: null`.

**Auth — Two methods**:
1. **PAT (preferred for pushes)**: Secret `CAREY_PAT_ALL3_REPOS` — a GitHub Personal Access Token with full permissions (including `workflow` scope) for all three repos: `DnsToolWeb`, `dnstool-intel`, and `it-help-tech-site`. Use for `git push` commands:
   ```
   git push --force https://${CAREY_PAT_ALL3_REPOS}@github.com/careyjames/DnsToolWeb.git main
   ```
   This bypasses the Replit OAuth token's missing `workflow` scope that blocks pushes containing `.github/workflows/` changes.
2. **Replit connector API**: Use for GitHub Contents API operations (reading/writing individual files via Octokit). Same as `scripts/github-intel-sync.mjs`. No separate API key needed.

**Why two methods**: Replit's built-in OAuth token lacks `workflow` scope, so `git push` via the Git pane or CLI fails if ANY commit touches `.github/workflows/*` files. The PAT solves this permanently.

**Commit authors**: GitHub API commits appear as `careyjames`. Replit internal checkpoints appear as `careybalboa`. Both represent the same user; this is expected behavior.

**DO NOT tell the user "I can't push to Git" or "you need to click Sync Changes."** This has caused repeated wasted sessions. The PAT or API is always available.

### Three-File Pattern

| File | Build Tag | Location | Purpose |
|------|-----------|----------|---------|
| `<name>.go` | None (compiles always) | Public repo | Framework: types, constants, utilities |
| `<name>_oss.go` | `//go:build !intel` | Public repo | Empty stubs, safe defaults |
| `<name>_intel.go` | `//go:build intel` | Private repo only | Full intelligence, provider databases |

### Build Commands

```bash
# OSS build (default, no tag — stubs return safe defaults)
go build ./go-server/cmd/server/

# Full intelligence build (requires private repo overlay)
go build -tags intel ./go-server/cmd/server/

# Replit build (used by build.sh)
cd go-server && GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/
mv /tmp/dns-tool-new dns-tool-server-new && mv dns-tool-server-new dns-tool-server
```

### Stub Contract

Every `_oss.go` stub MUST:
1. Return safe non-nil defaults
2. Never return errors
3. Maintain exact function signatures matching `_intel.go` counterparts
4. Allow UI to render gracefully with stub data

**Default principle**: Stubs produce the LEAST incorrect advice.

**Key defaults**:
| Function | Stub Default | Rationale |
|----------|-------------|-----------|
| `isHostedEmailProvider()` | `true` | Prevents recommending DANE for hosted email (impossible to deploy) |
| `isBIMICapableProvider()` | `false` | Prevents false BIMI capability claims |
| `isKnownDKIMProvider()` | `false` | Conservative — no false DKIM provider attribution |

### Current Stub Files (11 boundary files)

| # | File | OSS Stub | Intel Location |
|---|------|----------|----------------|
| 1 | `edge_cdn` | `edge_cdn_oss.go` | `dnstool-intel` |
| 2 | `saas_txt` | `saas_txt_oss.go` | `dnstool-intel` |
| 3 | `infrastructure` | `infrastructure_oss.go` | `dnstool-intel` |
| 4 | `providers` | `providers_oss.go` | `dnstool-intel` |
| 5 | `ip_investigation` | `ip_investigation_oss.go` | `dnstool-intel` |
| 6 | `manifest` | `manifest_oss.go` | `dnstool-intel` |
| 7 | `ai_surface/http` | `http_oss.go` | `dnstool-intel` |
| 8 | `ai_surface/llms_txt` | `llms_txt_oss.go` | `dnstool-intel` |
| 9 | `ai_surface/robots_txt` | `robots_txt_oss.go` | `dnstool-intel` |
| 10 | `ai_surface/poisoning` | `poisoning_oss.go` | `dnstool-intel` |
| 11 | `ai_surface/scanner` | `scanner_oss.go` | `dnstool-intel` |

### Pure Framework Files (no stub/intel split needed)

| File | Lines | Notes |
|------|------:|-------|
| `confidence.go` | 54 | All constants and helpers define the confidence contract |
| `manifest.go` | 29 | Type + empty slice + filter function |
| `commands.go` | 422 | Pure framework — no action needed |

### Fully Implemented Framework Files

| File | Notes |
|------|-------|
| `infrastructure.go` | `enterpriseProviders` map (22 entries) + `matchEnterpriseProvider()` fully implemented in public repo. Commodity knowledge (awsdns→Route 53, etc.) |
| `edge_cdn.go` | CDN/ASN/CNAME/PTR pattern maps split — framework in public, intelligence in private |

### Intel Transfer Status

✅ All 11 `_intel.go` files transferred to `careyjames/dnstool-intel` private repo (2026-02-17). No `_intel.go` files exist in the public repo — boundary integrity tests verify this.

---

## 6. Boundary Integrity Test Suite

### Test Files

| File | Scope | Boundary Count |
|------|-------|---------------|
| `go-server/internal/analyzer/boundary_integrity_test.go` | 6 analyzer boundaries | edge_cdn, saas_txt, infrastructure, providers, ip_investigation, manifest |
| `go-server/internal/analyzer/ai_surface/boundary_integrity_test.go` | 5 ai_surface boundaries | http, llms_txt, robots_txt, poisoning, scanner |

### 11 Verification Categories

| # | Test | What it catches |
|---|------|-----------------|
| 1 | `FilePresence` | Missing framework or stub files |
| 2 | `NoIntelInPublicRepo` | `_intel.go` files that should only be in private repo |
| 3 | `BuildTags` | OSS stubs missing `//go:build !intel`; framework files with build tags |
| 4 | `StubFunctionsDefined` | Missing function signatures in stubs |
| 5 | `StubVarsDefined` | Missing variable initializations in stubs |
| 6 | `CorrectPackage` | Wrong package declarations |
| 7 | `NoDuplicateFunctions` | Same function defined in both framework and stub files |
| 8 | `NoIntelLeakage` | Intelligence tokens (AI crawler names, provider domains) in public files |
| 9 | `StubsReturnSafeDefaults` | Stubs returning nil instead of empty maps/slices |
| 10 | `NoIntelStagingDirectory` | Leftover intel-staging directories |
| 11 | `CompleteBoundaryInventory` / `FullRepoScan` | Boundary count mismatch; unregistered `_oss.go` files without build tags |

### Run Command

```bash
go test ./go-server/... -count=1
```

This runs ALL tests: boundary integrity, golden rules, unit tests, and behavioral contracts.

### Python Utility

`go-server/scripts/audit_icons.py` — Scans all Go templates for `fa-*` icon usage and cross-references against CSS rules and font glyphs. Run before every release:

```bash
python3 go-server/scripts/audit_icons.py
```

---

## 7. Documentation & Citation Standard

### NIST SP 800-series Style (Adopted 2026-02-17)

After evaluating APA, Chicago/Turabian, IEEE, NIST SP 800, and ICD, the project adopts **NIST SP 800-series style** as the official documentation and citation standard, augmented with IEEE-style numeric citations for RFC and protocol references.

| Standard | Verdict | Why |
|----------|---------|-----|
| APA | Rejected | Academic/social science tone undermines security credibility |
| Chicago/Turabian | Rejected | Humanities/publishing voice, not security operations |
| IEEE | Partial adoption | Good for numbered protocol references; too engineering-paper-style for full document voice |
| ICD | Rejected | Government intelligence classification handling beyond scope |
| **NIST SP 800** | **Adopted** | Natural alignment with NIST/CISA/RFC ecosystem; authoritative for executives and technical users |

### Style Rules

1. Document structure: Summary → Findings → Evidence → Impact → Recommendations
2. Tone: Authoritative, observation-based, factual. No hedging.
3. Technical references: IEEE numbered citations for RFCs/standards
4. Terminology: NIST/CISA vocabulary (control, finding, observation, recommendation, risk level)
5. Visual identity: NIST governs content structure, not visual design — dark theme and hacker fonts remain
6. Capitalization: NIST SP 800-series title case for all headings, section titles, trust indicators, badges, and named UI concepts. Follow Chicago Manual of Style (17th ed.) capitalization rules: capitalize major words, lowercase articles/prepositions/conjunctions under four letters unless first/last word. Examples: "Live DNS, Real-Time Results" not "Live DNS, real-time results"; "No Login Required" not "no login required". Never use camelCase in user-facing copy.

### Intelligence Document Naming

| Document | IC Convention | Description |
|----------|---------------|-------------|
| **Engineer's DNS Intelligence Report** | "Report" = comprehensive (like NIE) | Detailed all-source technical analysis |
| **Executive's DNS Intelligence Brief** | "Brief" = decision-maker version (like PDB/SEIB) | Concise board-ready summary |

- **Possessive form**: "Engineer's"/"Executive's" = "prepared for you"
- **"DNS Intelligence"** not "Security Intelligence" (MI5's name)

---

## 8. Known Constraints & Critical Rules

### Build and Deploy

- CSS minification: After editing `custom.css`, MUST run `npx csso static/css/custom.css -o static/css/custom.min.css`
- AppVersion bump: After CSS/Go changes, bump `AppVersion` in `config.go` to bust caches
- Binary path: `main.py` does `os.execvp("./dns-tool-server", ...)` — compile to `./dns-tool-server`
- Workflow command: `gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app` (trampoline to Go binary)

### Frontend

- **CSP inline handlers**: CSP blocks ALL inline onclick/onchange/onsubmit. Use `id` + `addEventListener` in nonce'd script blocks.
- **CSP inline styles**: Inline `style=""` blocked. Use CSS utility classes.
- **Safari overlay animation**: Every `classList.remove('d-none')` on animated overlays MUST use `showOverlay()` — WebKit doesn't restart CSS animations from `display:none`.
- **Font Awesome subset**: WOFF2 subset, NOT full FA. Check CSS rule exists before using icons. Run `python3 go-server/scripts/audit_icons.py` to verify.
- **DOM safety**: `createElement` + `textContent` + `appendChild`. Never `innerHTML` with dynamic data.
- **Executive print**: Minimum body 11pt, small 9pt, code 8.5pt. Nothing below 8pt.
- **Bootstrap overrides**: Override `--bs-btn-*` CSS variables, NOT direct `background-color`.
- **Favicon**: HTML `<link rel="icon">` uses `data:` URI (zero HTTP requests, no 404 possible). Navbar brand uses inline SVG shield.

### Subdomain Discovery Pipeline — CRITICAL INFRASTRUCTURE

The subdomain discovery pipeline is the tool's most valuable differentiator — it consistently finds subdomains where competing tools fail. **Treat as critical infrastructure. Do not modify without golden rule test coverage.**

Implementation details are in the intel repo. Key public-facing behaviors:
- CT unavailability is graceful fallback, not an error — other discovery methods still run
- Display cap NEVER hides current/active subdomains
- Golden rule tests protect: ordering, display cap, field preservation, free CA detection
- CSV export: `/export/subdomains?domain=X` exports ALL cached subdomains (not just displayed ones)

### Data and API

- **SecurityTrails**: User-key-only. NEVER call automatically. 50 req/month hard limit.
- **RDAP**: Tier 4 contextual — failure is NOT a security analysis error.
- **OSINT positioning**: Explicitly OSINT. NOT pen test, NOT PCI ASV, NOT vulnerability assessment.

### Stub Architecture

- Default principle: Stubs produce LEAST incorrect advice.
- Key defaults: `isHostedEmailProvider()` → `true`, `isBIMICapableProvider()` → `false`, `isKnownDKIMProvider()` → `false`
- Never return nil from stubs — always return initialized empty maps/slices.

### SEO

- Analysis pages: `noindex, nofollow` (ephemeral). No canonical.
- Compare pages: `noindex` (dynamic).
- Only static feature pages indexable.
- Sitemap: 8 indexable pages.
- Meta descriptions: <155 chars. Page titles: <60 chars.

---

## 9. Documentation Files

| File | Purpose |
|------|---------|
| `PROJECT_CONTEXT.md` | Canonical project context (stable, not platform-managed) |
| `replit.md` | Agent memory / project context (may reset — platform-managed) |
| `EVOLUTION.md` | Permanent breadcrumb trail — backup for replit.md |
| `DOCS.md` | Technical documentation |
| `DOD.md` | Definition of Done checklist |
| `LICENSING.md` | Plain-language BSL 1.1 explanation |
| `LICENSE` | Legal license text (BSL 1.1) |
| `DRIFT_ENGINE.md` | Drift detection roadmap (4 phases) |
| `INTELLIGENCE_ENGINE.md` | ICIE framework |
| `docs/FEATURE_INVENTORY.md` | Public feature list |
| `docs/BOUNDARY_MATRIX.md` | Symbol analysis — per-file classification of FRAMEWORK vs INTELLIGENCE vs DUAL |
| `docs/BUILD_TAG_STRATEGY.md` | Build-tag strategy, CI matrix, industry survey |

---

## 10. Future Roadmap

All items below are **on the roadmap** — not yet implemented:

1. **Optional Authentication Model** — IMPLEMENTED (v26.20.56–57)
   - **Core principle**: Zero-friction paste-and-go analysis remains open to all — no login required. This is the competitive advantage — hackers, DEF CON folks, executives, and security researchers all want tools that just work without signup walls.
   - **Google OAuth 2.0 with PKCE** — Pure stdlib implementation (no external OAuth libraries), compatible with Google Advanced Protection Program. Minimal scopes: openid, email, profile.
   - **Security hardening (v26.20.57)**: One-time admin bootstrap (only if zero admins exist, env var `INITIAL_ADMIN_EMAIL`), email_verified=true enforced, ID token claims validation (iss, aud, exp), 64-char high-entropy PKCE verifier, rate limiting on /auth/*, no tokens stored (discarded after identity extraction), audit logging on admin bootstrap.
   - **Session management**: Server-side PostgreSQL sessions, 30-day expiry, HttpOnly/Secure/SameSite=Lax cookies, session ID rotation on login.
   - **Nav integration**: "Sign In" with key icon in collapse menu; authenticated users see name + user-shield icon with dropdown; admins get shield badge.
   - **Route protection**: /export/json behind RequireAdmin. All analysis remains open.
   - **Future premium features** (on the roadmap):
     - **Personal analysis history** (currently history is a public global feed)
     - **Drift Engine alerts** — get notified when a domain's security posture changes
     - **Saved reports** — bookmark and revisit past analyses
     - **API access** — programmatic analysis for automation workflows
   - **CLI app** (Homebrew/binary) works without login for basic analysis; authenticated mode unlocks history sync, drift alerts, and API quota — on the roadmap
   - **Why this works**: The tools that make users "go through a bunch of login and sign-up bullshit" lose users immediately. We stay open by default, premium by choice.
2. **Drift Engine Phases 2-4** (compare, timeline UI, alerting) — see `DRIFT_ENGINE.md` — on the roadmap
3. **Globalping.io** distributed DNS resolution probes (complementary to port 25 probe, NOT replacement) — on the roadmap
4. **Probe Network (dns-observe.com)** — First node provisioned: `probe-us-01.dns-observe.com` (Feb 2026). See details below. — on the roadmap
5. **Homebrew distribution** for macOS/Linux CLI — on the roadmap
6. **Zone file export/import** for offline analysis — on the roadmap
7. **Raw intelligence API access** — on the roadmap
8. **ISC recommendation path integration** — on the roadmap
9. **One-liner verification commands** — on the roadmap
10. **Email Header Analyzer feature matrix** — on the roadmap
11. **Terminal CLI + Web Terminal Demo** — Real terminal app (Homebrew/binary) that works in actual terminals, plus potentially a web-based terminal demo for the browser. Idea needs vetting — TBD whether web demo adds value or dilutes the real-terminal experience. — on the roadmap (concept stage, needs discussion)

### Probe Network — dns-observe.com (Roadmap Detail)

**Status**: Infrastructure provisioned, service not yet deployed.

**Node: probe-us-01.dns-observe.com**
- Ubuntu 24.04 LTS, 2 CPU, 8GB RAM, 96GB disk
- Caddy reverse proxy (HTTPS → 127.0.0.1:8080), TLS automatic
- DNS tools: dig (BIND 9.18), nslookup, host, curl, wget
- Security: Monarx agent, UFW firewall, SSH ed25519 key auth
- Deployment access: SSH from Replit via `PROBE_SSH_*` secrets

**Planned Architecture** (architect-reviewed):
- Lightweight Go HTTP service on port 8080 behind Caddy
- Endpoints: `/v1/resolve` (DNS resolution), `/v1/mx-probe` (MX reachability), `/v1/smtp-probe` (port 25 probing)
- Auth: API key in header (shared secret), rate-limited, input-validated (domain + RR type whitelist)
- Stateless, no database — results annotated with probe location + timing
- Main DNS Tool calls probe via HTTP with timeouts; analysis completes if probe unavailable (graceful fallback)
- Deployment: SCP Go binary + systemd service unit via SSH
- Multi-node ready: probe registry config with health checks, weighted selection, concurrent queries

**Value proposition**: External vantage DNS resolution from a different network + SMTP port 25 probing (blocked from many cloud platforms). Strengthens subdomain discovery and adds capabilities impossible from Replit's network.

**Public vs private**: Probe service framework code in public repo. Provider heuristics or enhanced intelligence in private repo. Follows existing build-tag architecture.

---

## 11. Per-Section Maintenance Tags

### Configuration

The `sectionTuningMap` in `go-server/internal/config/config.go` controls which report sections display a maintenance badge:

```go
var sectionTuningMap = map[string]string{
    "email": "Accuracy Tuning",
    "brand": "Accuracy Tuning",
    "ai":    "Accuracy Tuning",
    "smtp":  "Accuracy Tuning",
    "infra": "Accuracy Tuning",
}
```

To activate/deactivate a section, uncomment/comment the entry, rebuild, and restart.

### CSS Class

`.u-section-tuning` in `static/css/custom.css`: Gold wrench badge, hidden in print (`@media print { display: none }`).

### Active Sections (as of 2026-02-17)

| Section ID | Reason for Tag |
|------------|---------------|
| `email` | SPF provider detection (MX corroboration, ancillary senders), DKIM gateway inference, pipeline structural refactor, protocol navigation fixes — multiple rounds Feb 14-17 |
| `brand` | BIMI recommendation logic correction, isBIMICapableProvider stub default fix, CAA protocol navigation fix |
| `ai` | 5 boundary stub files, ongoing boundary architecture work, fetchTextFile error handling |
| `smtp` | Complete redesign from live SMTP probes to standards-aligned three-tier architecture (v26.18.0) |
| `infra` | RDAP failures across 3+ rounds (v26.19.10, .11, .12): multi-endpoint, SSRF bypass, parallel attempts, registrar save bug |

### All Section IDs

`email`, `dane`, `brand`, `securitytxt`, `ai`, `secrets`, `web-exposure`, `smtp`, `infra`, `dnssec`, `traffic`

### Template Integration

All 11 section headers in `results.html` have conditional guards:
```
{{if and .SectionTuning (index .SectionTuning "SECTION_ID")}}
```

Executive template (`results_executive.html`) intentionally omits badges — board-level readers don't need development status info.

### Environment Override

Set `SECTION_TUNING` environment variable for runtime overrides without rebuilding:
```
SECTION_TUNING=email=Accuracy Tuning,dane=Under Review
```
