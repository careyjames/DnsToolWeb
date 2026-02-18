---
name: dns-tool
description: DNS Tool project rules, architecture, and conventions. Use whenever working on this project — covers build tags, stub contracts, CSP constraints, testing requirements, version bumps, naming conventions, and critical anti-patterns to avoid.
---

# DNS Tool — Agent Skill

This skill contains the critical rules and architecture knowledge for the DNS Tool project. Load this before making any changes.

## Session Startup

1. Read `replit.md` — quick-reference config (may reset between sessions)
2. Read `PROJECT_CONTEXT.md` — canonical, stable project context
3. Read `EVOLUTION.md` — permanent breadcrumb trail, backup if `replit.md` resets
4. Check the "Failures & Lessons Learned" section in `EVOLUTION.md` before making changes
5. If `replit.md` appears truncated or reset, restore key pointers from `PROJECT_CONTEXT.md` and `EVOLUTION.md`
6. Run `find go-server -name "*_intel*"` — if ANY `_intel.go` or `_intel_test.go` files exist locally, they must be pushed to `dnstool-intel` via the sync script and deleted immediately (see "Cross-Repo Sync via GitHub API" below)

## Mandatory Post-Edit Rules

### After ANY Go code changes
```bash
go test ./go-server/... -count=1
```
This runs boundary integrity tests that catch intelligence leaks, stub contract breakage, duplicate symbols, and architecture violations. **Never skip this.**

### After CSS changes
```bash
npx csso static/css/custom.css -o static/css/custom.min.css
```

### Version Bump — MANDATORY EVERY TIME (cache-busting)
**After EVERY change (Go, CSS, templates — no exceptions)**, bump the patch number in `AppVersion` in `go-server/internal/config/config.go`. The version string busts browser caches for all static assets. If you don't bump it, the user cannot test your changes — they'll see stale cached content. This is non-negotiable and must happen before rebuild.

### Build and Deploy Chain — CRITICAL (caused multiple regressions)

The launch chain is: `gunicorn → main.py → os.execvp("./dns-tool-server")`. Python is a trampoline only — it replaces itself with the Go binary. There is NO Flask, NO Python logic at runtime.

```bash
./build.sh   # Compiles Go → ./dns-tool-server
```

**Common mistake**: Changing Go code, bumping AppVersion, but NOT rebuilding the binary. The workflow runs `main.py` which execs the **pre-compiled** binary. If you don't rebuild, your changes don't exist. The full sequence after ANY changes:
1. Bump `AppVersion` patch number in `go-server/internal/config/config.go`
2. Run `go test ./go-server/... -count=1`
3. Run `./build.sh`
4. Restart the workflow
5. Verify the new version appears in the server startup log

**Binary path**: Must compile to `./dns-tool-server` (project root). `main.py` does `os.execvp("./dns-tool-server", ...)` — wrong path = app won't start.

**Workflow command**: `gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app`

## Two-Repo Build-Tag Architecture

Two repositories with Go build tags:
- **DnsToolWeb** (public): Framework code + `_oss.go` stubs — **this is the repo we work in**
- **dnstool-intel** (private): `_intel.go` files with proprietary intelligence

### Cross-Repo Sync via GitHub API

The Replit GitHub integration (Octokit) has full `repo` scope, enabling direct read/write to `careyjames/dnstool-intel` via the GitHub API.

**Sync script**: `scripts/github-intel-sync.mjs`
```bash
node scripts/github-intel-sync.mjs list                              # List all Intel repo files
node scripts/github-intel-sync.mjs read <path>                       # Read a file from Intel repo
node scripts/github-intel-sync.mjs push <local> <remote> [message]   # Push local file to Intel repo
node scripts/github-intel-sync.mjs delete <path> [message]           # Delete file from Intel repo
node scripts/github-intel-sync.mjs commits [count]                   # Show recent commits
```

**When to use**: Push `_intel.go` files (provider databases, intelligence code) to the Intel repo. Never commit `_intel.go` files to DnsToolWeb — they expose proprietary patterns even with build tags (source code is visible in public Git history).

**CRITICAL**: If you create or modify `_intel.go` files, push them to `dnstool-intel` via the sync script and DELETE them from the local DnsToolWeb working directory. Files with `//go:build intel` tags won't compile in the OSS build but their source code is visible in the public repo history.

### Git Operations — USE THE GITHUB API (Recurring Session Failure)

**The Replit shell blocks `git` CLI commands.** You will get "Avoid changing .git repository" errors. Do NOT tell the user you can't do Git operations — you CAN, via the GitHub API.

The GitHub integration (Octokit, full `repo` scope) gives you complete read/write access to BOTH repos:
- `careyjames/DnsToolWeb` (public)
- `careyjames/dnstool-intel` (private)

**When the Replit Git panel fails** (PUSH_REJECTED, diverged branches, can't pull/sync), resolve it via the GitHub API:

```javascript
// Pattern: Push local changes to DnsToolWeb when Git panel fails
// 1. Get remote HEAD: octokit.git.getRef({ ref: 'heads/main' })
// 2. Get base tree: octokit.git.getCommit({ commit_sha: headSha })
// 3. Create blobs for changed files: octokit.git.createBlob()
// 4. Create new tree: octokit.git.createTree({ base_tree, tree: entries })
// 5. Create commit: octokit.git.createCommit({ tree, parents: [remoteHead] })
// 6. Update ref: octokit.git.updateRef({ ref: 'heads/main', sha: newCommit })
```

**To delete a file from the remote**, include it in the tree with `sha: null`.

**Commit author**: GitHub API commits use `careyjames` (the GitHub identity). Replit checkpoint commits use `careybalboa` (Replit's internal identity). Both are normal — they represent the same person.

**This is NOT optional knowledge.** Multiple sessions have wasted time telling the user "I can't push to Git" or "you need to click Sync Changes" when the API was available the whole time. The GitHub API can do everything Git CLI can do. Use it.

### Three-File Pattern
| File | Build Tag | Purpose |
|------|-----------|---------|
| `<name>.go` | None | Framework: types, constants, utilities |
| `<name>_oss.go` | `//go:build !intel` | Stubs returning safe defaults |
| `<name>_intel.go` | `//go:build intel` | Full intelligence (private repo only) |

### Stub Contract — CRITICAL
1. Return safe **non-nil** defaults (empty maps/slices, never nil)
2. **Never** return errors
3. Exact function signatures matching `_intel.go` counterparts
4. Default principle: stubs produce the **least incorrect advice**

Key stub defaults:
- `isHostedEmailProvider()` → `true` (prevents recommending DANE for hosted email)
- `isBIMICapableProvider()` → `false` (prevents false BIMI claims)
- `isKnownDKIMProvider()` → `false` (conservative)

### 11 Boundary Stub Files
`edge_cdn`, `saas_txt`, `infrastructure`, `providers`, `ip_investigation`, `manifest`, `ai_surface/http`, `ai_surface/llms_txt`, `ai_surface/robots_txt`, `ai_surface/poisoning`, `ai_surface/scanner`

## CSP (Content Security Policy) — CRITICAL

- **No inline handlers**: `onclick`, `onchange`, `onsubmit` are ALL blocked by CSP
- Use `id` + `addEventListener` in nonce'd `<script>` blocks instead
- **No inline styles**: `style=""` is blocked. Use CSS utility classes
- **DOM safety**: `createElement` + `textContent` + `appendChild`. Never `innerHTML` with dynamic data

## Safari/iOS Compatibility — TOP PRIORITY

- **Overlay animations**: Every `classList.remove('d-none')` on animated overlays MUST use `showOverlay()` — WebKit doesn't restart CSS animations from `display:none`
- Always test Safari compatibility for frontend changes

## SecurityTrails — NEVER CALL AUTOMATICALLY

- 50 requests/month **hard limit**
- User-provided API key ONLY on DNS History and IP Intelligence pages
- **Never** call SecurityTrails automatically in the analysis pipeline
- Once exhausted, the key is dead for the rest of the month

## Font Awesome — WOFF2 Subset Only

- NOT full Font Awesome. We use a WOFF2 subset (~110 glyphs)
- Check CSS rule exists before using any new `fa-*` icon
- Run `python3 go-server/scripts/audit_icons.py` to verify before releases
- ALL FA CSS files must use `staticVersionURL` cache-busting (past regression: FA CSS was the only unversioned stylesheet)
- If an icon doesn't render, check THREE things: (1) CSS class defined? (2) Same CSS line as a working icon? (3) CSS file cache-busted?
- Do NOT just check the font file and declare victory — past sessions confirmed glyph existed but icon was still invisible due to caching

## No-Mail Domain Classification (v26.19.38+)

Three-tier classification for domains that don't send/receive email:

| Classification | Trigger | Template | Color |
|----------------|---------|----------|-------|
| `no_mail_verified` | Null MX + SPF -all + DMARC reject | Green alert, shield icon, "Fully Hardened" | success |
| `no_mail_partial` | Null MX present but missing SPF -all or DMARC reject | Yellow alert, exclamation triangle, "Incomplete Hardening" + missing steps + recommended records | warning |
| `no_mail_intent` | No MX records + SPF -all but no Null MX | Blue info alert, graduation cap, educational section: "It looks like this is meant to be a no-mail domain" with three RFC standards (7505, 7208, 7489) | info |

All three tiers set `isNoMail = true` and generate recommended DNS records via `buildNoMailStructuredRecords()`. The educational `no_mail_intent` section shows the three RFC standards with exact DNS records to copy.

**Key code locations**: `classifyMailPosture()` in `remediation.go`, template sections in `results.html` around line 637+.

## Intelligence Document Naming

| Document | Convention |
|----------|-----------|
| **Engineer's DNS Intelligence Report** | Comprehensive technical analysis ("Report" = like NIE) |
| **Executive's DNS Intelligence Brief** | Board-ready summary ("Brief" = like PDB/SEIB) |

- Possessive form: "Engineer's"/"Executive's" = "prepared for you"
- "DNS Intelligence" — never "Security Intelligence" (that's MI5's name)
- TLP: FIRST TLP v2.0, default TLP:AMBER

## Reality Check Rule

Every homepage claim, schema statement, and documentation assertion **must** be backed by implemented code. Use "on the roadmap" for future items. Use "context" instead of "verification" for informational features.

## OSINT Positioning

- Explicitly OSINT
- NOT pen test, NOT PCI ASV, NOT vulnerability assessment
- Observation-based language — never making definitive claims beyond what the data shows

## Version Bumps

Update `AppVersion` in `go-server/internal/config/config.go`. Format: `YY.WW.PATCH` (e.g., `26.19.27`). **Bump the PATCH number after every single change** — this is the cache-buster. No bump = user sees stale content = untestable.

## Key File Locations

| File | Purpose |
|------|---------|
| `go-server/internal/config/config.go` | Version, maintenance tags |
| `go-server/internal/analyzer/orchestrator.go` | Analysis pipeline orchestrator |
| `go-server/templates/results.html` | Engineer's Report template |
| `go-server/templates/results_executive.html` | Executive Brief template |
| `PROJECT_CONTEXT.md` | Canonical project context |
| `EVOLUTION.md` | Permanent breadcrumb trail |

## Print/PDF Rules

- Executive Brief print: minimum body 11pt, small 9pt, code 8.5pt. **Nothing below 8pt**
- PDF `<title>` format: `Engineer's DNS Intelligence Report — {{.Domain}} - DNS Tool` (becomes PDF filename)
- Bootstrap overrides: override `--bs-btn-*` CSS variables, NOT direct `background-color`
- Bootstrap specificity: use double-class selectors (`.btn.btn-tlp-red`, not `.btn-tlp-red`) to override Bootstrap defaults

## Naming Sync Points (5 locations per document — all must match)

When changing report names, check ALL five:
1. `<title>` tag (becomes PDF filename)
2. Print header (`.print-report-title`)
3. Screen header (`<h1>`)
4. OG/Twitter meta tags
5. Button/link labels in the OTHER report template

Grep for shortened variants before committing. Past regressions: "Executive's Intelligence Briefs" (missing "DNS"), "View Engineer's Report" (missing full name).

## Known Regression Pitfalls

These have caused repeated regressions — check EVOLUTION.md "Failures & Lessons Learned" for details:
- **Intel files left in public repo** — `_intel.go` and `_intel_test.go` files committed to DnsToolWeb expose proprietary patterns in public Git history even with build tags. Always push to dnstool-intel via sync script and delete locally. (Feb 2026 incident: `golden_rules_intel_test.go` with enterprise provider patterns was public.)
- **"I can't push to Git"** — WRONG. The Replit shell blocks `git` CLI but the GitHub API (Octokit) has full `repo` scope on BOTH repos. Use the API to push changes, resolve diverged branches, and delete files. Multiple sessions have wasted time on this. See "Git Operations" section above.
- CSP inline handlers added then silently failing (recurring v26.14–v26.16)
- Font Awesome icons used without checking subset CSS rules exist
- PDF/print font sizes dropping below minimums (recurring v26.15–v26.16)
- Stub functions returning nil instead of empty defaults
- SecurityTrails called in analysis pipeline (budget exhaustion)
- Bootstrap button styling done with direct properties instead of CSS variables
- Go code changed but binary NOT rebuilt (changes don't exist until `./build.sh`)
- AppVersion bumped in config.go but binary not rebuilt (cache-buster not applied)
- CSS edited but `custom.min.css` not regenerated (server loads minified version)
- Report names shortened inconsistently across 5 sync points
- Font Awesome CSS not cache-busted (missing `staticVersionURL` while other CSS had it)
- RDAP treated as critical failure instead of Tier 4 contextual (alarming users for non-security data)

## Subdomain Discovery Pipeline — DO NOT BREAK (Critical Infrastructure)

Subdomain discovery is the tool's crown jewel. It consistently finds subdomains where competing tools fail. This was broken for a long time before being fixed. **Treat the pipeline as critical infrastructure.**

### Pipeline Sequence (order matters)
1. **CT fetch** → `crt.sh` query with 30s timeout (10MB body limit)
2. **Deduplication** → `deduplicateCTEntries()` by serial_number
3. **CT processing** → `processCTEntries()` extracts subdomain names from CT SANs
4. **DNS probing** → `probeCommonSubdomains()` probes ~90 common prefixes
5. **CNAME traversal** → discovers additional infrastructure via CNAME chains
6. **Enrichment** → `enrichSubdomainsV2()` resolves each subdomain, updates `is_current`
7. **Recount** → `currentCount`/`expiredCount` recalculated AFTER enrichment
8. **Sort** → `sortSubdomainsSmartOrder()` — current first, then historical by date desc
9. **Cache** → `setCTCache()` stores sorted results
10. **Display cap** → `applySubdomainDisplayCap()` — never hides current subdomains

### DO NOT TOUCH without golden rule test coverage
- `processCTEntries()` — CT → subdomain extraction
- `probeCommonSubdomains()` — DNS probing wordlist and resolution
- `enrichSubdomainsV2()` — live resolution and `is_current` mutation
- The pipeline ORDER: enrichment MUST happen before sort and count

### Key Invariants (protected by golden rule tests)
- Current subdomains ALWAYS appear before historical in display
- Display cap NEVER hides current/active subdomains
- CT unavailability gracefully falls back to DNS probing (not an error)
- All fields (`source`, `first_seen`, `cname_target`, `cert_count`) survive sort
- `is_current` is authoritative after enrichment — template uses it for badges

### Why it works where others fail
CT provides breadth (every cert ever issued), DNS probing adds common service names that may not have certs, CNAME traversal discovers infrastructure behind aliases, and enrichment filters to what's actually live. The combination catches subdomains that any single method would miss.

### Past failure: Sort-before-enrichment bug (v26.19.29)
Sorting was originally done before `enrichSubdomainsV2()`, which meant CT entries with expired certs but still-resolving subdomains were classified as "historical" before enrichment could update `is_current = true`. Fix: sort AFTER enrichment.

## Drift Engine (Phase 2)

The drift engine detects posture changes between analyses. Key files:
- `posture_hash.go` — Canonical SHA-256 posture hashing (public, framework-level)
- `posture_diff.go` — Structured diff computation: compares two analysis results, returns which fields changed (public)
- `posture_diff_oss.go` — OSS severity classification for drift fields (public stub, `!intel` build tag)
- `DRIFT_ENGINE.md` — Public summary only. Full roadmap lives in the private `dnstool-intel` repo.

### Drift diff architecture
- **Public** (`posture_diff.go`): `ComputePostureDiff(prev, curr map[string]any) []PostureDiffField` — raw field-by-field comparison
- **Build-tagged** (`posture_diff_oss.go`): `classifyDriftSeverity()` — maps changes to Bootstrap severity classes (danger/warning/success/info)
- **Handler**: Uses `GetPreviousAnalysisForDrift` query to get previous full_results for diff computation
- **Template**: Drift alert shows structured table of changed fields with severity-colored badges, "View Previous Report" link, and clickable hash previews

### Drift severity rules (OSS defaults)
- DMARC policy downgrade (reject → none): `danger`
- DMARC policy upgrade (none → reject): `success`
- Security status degradation (pass → fail): `danger`
- Security status improvement (fail → pass): `success`
- MX/NS record changes: `warning`
- Other changes: `info`

## Anti-Patterns to Avoid

1. **Don't use inline onclick/onchange** — CSP will block it silently
2. **Don't return nil from stubs** — return empty maps/slices
3. **Don't call SecurityTrails automatically** — 50/month limit
4. **Don't use innerHTML with dynamic data** — XSS risk
5. **Don't skip `go test`** — boundary tests catch leaks and breakage
6. **Don't claim unimplemented features** — say "on the roadmap"
7. **Don't use full Font Awesome** — subset only, verify CSS rules exist
8. **Don't forget CSS minification** — `npx csso` after every CSS edit
9. **Don't hardcode foreign keys** — violates FK constraints
10. **Don't use `style=""`** — CSP blocks inline styles
11. **NEVER leave `_intel.go` or `_intel_test.go` files in DnsToolWeb** — push to `dnstool-intel` via `node scripts/github-intel-sync.mjs push` and delete locally. Build tags don't hide source code from public Git history. This has caused a real proprietary data leak (Feb 2026).
12. **Don't assume the Intel repo is inaccessible** — the GitHub integration gives full read/write access via `scripts/github-intel-sync.mjs`. Use it.
