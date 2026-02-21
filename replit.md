# DNS Tool — Domain Security Audit

## Overview
OSINT platform for RFC-compliant domain security analysis. Go/Gin backend, Bootstrap dark theme frontend, PostgreSQL database. BSL 1.1 license with two-repo open-core architecture.

## Key Files
- **PROJECT_CONTEXT.md** — Canonical project context (stable, comprehensive). READ THIS FIRST.
- **EVOLUTION.md** — Permanent breadcrumb trail. Backup if this file resets.
- **AUTHORITIES.md** — Authoritative Sources Registry. Every standard/RFC/authority we cite. Verify here before claiming anything is a "standard."
- **DOCS.md** — Technical documentation
- **DOD.md** — Definition of Done checklist

## Quality Gates — MANDATORY (Never Regress)
| Tool | Target | Notes |
|------|--------|-------|
| Lighthouse Performance | 100 | 98–100 acceptable (network variance) |
| Lighthouse Best Practices | 100 | < 100 = real UX error, fix immediately |
| Lighthouse Accessibility | 100 | < 100 = broken markup, fix immediately |
| Lighthouse SEO | 100 | < 100 = missing metadata, fix immediately |
| **Observatory** | **130** | **Never decrease. Security only moves forward.** |
| **SonarCloud Reliability** | **A** | **Zero new bugs. Non-negotiable.** |
| **SonarCloud Security** | **A** | **Zero new vulnerabilities. Non-negotiable.** |
| **SonarCloud Maintainability** | **A** | **Zero new code smells. Non-negotiable.** |

## Development Process — Research First, Build Correctly
No "build fast, clean up later." Research the best-practices path first (cite RFCs, standards). Design before implementing. Write tests first. Check quality gates during development, not after. The tests, quality gates, and documentation exist to prevent rework — use them.

## Critical Rules (Summary)
1. **After ANY Go code changes**: Run `go test ./go-server/... -count=1` before considering work done.
2. **After CSS changes**: Run `npx csso static/css/custom.css -o static/css/custom.min.css` — **server loads minified file only; skip this and changes won't appear**
3. **Version bumps**: Update `AppVersion` in `go-server/internal/config/config.go`
4. **Build**: `./build.sh` compiles to `./dns-tool-server`; `main.py` is the gunicorn trampoline.
5. **CSP**: No inline onclick/onchange/style="". Use addEventListener in nonce'd script blocks.
6. **Safari scan navigation**: NEVER use `location.href` to start a scan that shows an overlay with timer/phases — WebKit kills running JS on navigation, freezing the overlay at 0s. Use `fetch()` + `document.write()` + `history.replaceState()` instead. Always call `showOverlay()` (double-rAF animation restart) before starting the fetch. After `document.close()`, always call `globalThis.scrollTo(0, 0)` to reset scroll position. Pattern: main.js, results.html, history.html, dossier.html.
7. **SecurityTrails**: User-key-only. NEVER call automatically. 50 req/month hard limit.
8. **Reality Check**: Every claim must be backed by implemented code. Use "on the roadmap" for future items.
9. **Font Awesome**: WOFF2 subset only. Check CSS rule exists before using new icons.
10. **Stubs**: `_oss.go` files return safe non-nil defaults, never errors.
11. **Capitalization**: NIST/Chicago title case for all user-facing headings, badges, trust indicators. Never camelCase in UI copy.
12. **pointer-events**: NEVER apply `pointer-events: none` to `body` or `html` — kills Chrome wheel/trackpad scroll. Use targeted selectors on interactive elements instead.
14. **Print-only elements**: ALL print-only elements (`.print-report-header`, `.print-domain-banner`, `.print-report-footer`) MUST have `display: none !important` in the screen stylesheet. They are shown via `display: block !important` inside `@media print`. Without the screen hide rule, `document.write()` loads show the print header on screen (the CSS race condition). Never add print-only template content without a corresponding screen hide rule.
13. **Mobile verification**: EVERY CSS/template change must be verified at 375px width. Buttons need `white-space: nowrap`. No `flex: 1` + `min-width: 0` on buttons without `nowrap`. See DOD.md "Mobile UI Verification" checklist.
15. **CSS cache busting**: When making iterative CSS changes, bump `Version` in config.go EACH iteration — the browser caches `custom.min.css?v=VERSION` aggressively. Same version = stale CSS in Replit preview. Always bump before asking user to evaluate visual changes.
16. **Homepage ICAE hero card**: Structure is `div.icae-hero-card` → `a.icae-hero-statement` (the confidence statement) + `div.icae-hero-protocols` (protocol badges). Statement and protocols are SEPARATE blocks with a `border-top` divider. Protocols use the existing `.icae-badge` pill buttons. Do NOT flatten protocols into inline text — the pill badges are the approved design. Do NOT use `<span>` for block layout — use `<div>` elements (or `display:block` on `<a>`) to guarantee block stacking.

## /dev/null Ephemeral Scan (v26.21.11)
- **User-selectable checkbox** in Advanced Options: `/dev/null Scan` — full analysis, zero persistence.
- **Auto-enables**: Ticking `/dev/null` auto-enables Expanded Exposure Checks (user can still uncheck).
- **Skips**: `saveAnalysis()`, `InsertUserAnalysis()`, `icae.EvaluateAndRecord()`, `RecordAnalysis()` analytics, drift lookup.
- **Logic**: `ephemeral = devNull || (hasNovelSelectors && !isAuthenticated)` — devNull flag overrides.

## Community Signals (v26.21.11)
- Discoverable content for security researchers. All signals carry RFC 1392 legal disclaimers.
- **INTENTIONAL design elements**: Some UI elements use reduced opacity or subtle placement by design. These are deliberate community signals — do NOT alter their visibility or "fix" them.

## Content-Usage Directive Detection (v26.21.9, updated v26.21.38)
- **IETF AI Preferences working group**: Detects `Content-Usage:` directives in robots.txt. Active IETF draft (draft-ietf-aipref-attach), NOT a ratified standard.
- **Parser**: `parseContentUsageDirectives()` in `scanner.go` — space-separated key=value format per draft ABNF.
- **Recognized keys**: `ai`, `train-ai`, `ai-training`, `ai-inference`. Deny values: n, no, none, disallow.
- **Flags**: `ai_denied` when any recognized key has a deny value. Observation-based language only.
- **Display**: New section in AI Surface results between crawler governance and poisoning checks.
- **Governance signal**: Content-Usage presence triggers "AI governance signals observed" in summary.
- **Our robots.txt**: Uses `Content-Usage: ai=allow`, `ai-training=allow`, `ai-inference=allow`. No redundant bot-specific blocks.

## Authentication (v26.20.56–57)
- **Google OAuth 2.0 + PKCE** — Pure stdlib, no external OAuth libraries. Advanced Protection compatible.
- **Env vars**: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `INITIAL_ADMIN_EMAIL` (all optional — app runs without them).
- **One-time admin bootstrap**: `INITIAL_ADMIN_EMAIL` grants admin only if zero admins exist in DB.
- **Security**: email_verified enforced, ID token claims validated, rate-limited /auth/*, no tokens stored, audit logging.
- **Nav**: "Sign In" (fa-key) in collapse menu; authenticated dropdown with fa-user-shield; admin badge fa-shield.
- **Route protection**: /export/json requires admin. All analysis remains no-login-required.

## SMTP Probe Infrastructure (v26.20.87–88)
- **Remote probe mode**: `SMTP_PROBE_MODE=remote` calls external probe API instead of local port 25.
- **Probe server**: `probe-us-01.dns-observe.com` — Python 3 API v2.0 (`/opt/dns-probe/probe_api.py`), systemd unit `dns-probe.service`, pre-existing Caddy reverse proxy (only Caddyfile updated).
- **Authentication**: Shared-secret via `X-Probe-Key` header. Returns 401 without valid key. Go backend sends `PROBE_API_KEY` automatically.
- **Rate limiting**: 30 requests per 60 seconds per client IP. Returns 429 when exceeded.
- **Multi-port probing**: Ports 25 (SMTP), 465 (SMTPS), 587 (submission) probed in parallel per host. Results in `all_ports` / `multi_port` field.
- **Banner capture**: First 200 chars of SMTP banner captured for intelligence fingerprinting.
- **Secrets**: `PROBE_API_URL`, `PROBE_API_KEY`, `PROBE_SSH_HOST`, `PROBE_SSH_USER`, `PROBE_SSH_PRIVATE_KEY` (all configured).
- **API endpoints**: POST `/probe/smtp` (with `{"hosts": [...], "ports": [25,465,587]}`) and GET `/health`.
- **Fallback**: If remote probe fails (network, 401, 429, invalid response), falls back to local direct SMTP probing (`force` mode).
- **SSH access**: `ssh -i <key> root@probe-us-01.dns-observe.com` — key requires newline reformatting from secret storage.
- **OPSEC note**: Internal port 8025 bound to loopback only; only 443 exposed externally. Architect reviewed: acceptable.
- **Roadmap**: See EVOLUTION.md "Probe Server Roadmap / Future Work" for remaining items (health monitoring, multi-region, firewall hardening).

## Engines
- **ICIE** — Intelligence Classification & Interpretation Engine (analysis logic)
- **ICAE** — Intelligence Confidence Audit Engine (accuracy tracking). Package: `go-server/internal/icae/`. DB tables: `ice_*` (legacy prefix, not renamed). Two layers per protocol: collection + analysis. Maturity: development → verified → consistent → gold → gold_master. 45 deterministic test cases.

## Repositories (GitHub Canonical, Codeberg Mirror)
- **Webapp**: `careyjames/dns-tool-web` (GitHub, canonical) → `careybalboa/dns-tool-web` (Codeberg, read-only mirror)
- **Intel**: `careyjames/dns-tool-intel` (GitHub, canonical) → `careybalboa/dns-tool-intel` (Codeberg, mirror)
- **CLI**: `careyjames/dns-tool-cli` (GitHub, canonical) → `careybalboa/dns-tool-cli` (Codeberg, read-only mirror)
- GitHub→Codeberg sync via `.github/workflows/mirror-codeberg.yml`. SonarCloud runs on GitHub (primary).

## Architecture Quick Reference
- **Build tags**: `//go:build intel` (private) / `//go:build !intel` (public OSS stubs)
- **12 stub files**: edge_cdn, saas_txt, infrastructure, providers, ip_investigation, manifest, posture_diff, ai_surface/{http,llms_txt,robots_txt,poisoning,scanner}
- **Intel repo sync (GitHub)**: `node scripts/github-intel-sync.mjs` — reads/writes `careyjames/dns-tool-intel` via GitHub API (canonical).
- **Webapp sync (Codeberg)**: `node scripts/codeberg-webapp-sync.mjs` — reads/writes `careybalboa/dns-tool-web` via Forgejo API (mirror).
- **Intel repo sync (Codeberg)**: `node scripts/codeberg-intel-sync.mjs` — reads/writes `careybalboa/dns-tool-intel` via Forgejo API (mirror). Uses `CODEBERG_FORGEJO_API` token.
- **Manual sync**: `./scripts/github-to-codeberg-sync.sh` — full-repo mirror (all branches + tags).
- NEVER leave `_intel.go` files in this repo — push to Intel repo and delete locally.
- **DNS library**: `codeberg.org/miekg/dns` v0.6.52 (v2). Migrated from `github.com/miekg/dns` v1.1.72 in v26.20.76.
- **Reports**: "Engineer's DNS Intelligence Report" (technical) / "Executive's DNS Intelligence Brief" (board-ready)
- **TLP**: FIRST TLP v2.0, default TLP:AMBER
- **Architecture page**: `/architecture` — interactive Mermaid diagrams (CSP-compliant, post-render JS for SVG colors)
- **CI**: SonarCloud on GitHub (`.github/workflows/sonarcloud.yml`), Codeberg mirror sync (`.github/workflows/mirror-codeberg.yml`), Forgejo Actions on Codeberg (redundant)

## Note About This File
This file may be regenerated by the Replit platform. If it appears truncated or reset, the full project context lives in `PROJECT_CONTEXT.md` and `EVOLUTION.md`. Keep this file lightweight — detailed context belongs in PROJECT_CONTEXT.md.
