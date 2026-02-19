# DNS Tool — Domain Security Audit

## Overview
OSINT platform for RFC-compliant domain security analysis. Go/Gin backend, Bootstrap dark theme frontend, PostgreSQL database. BSL 1.1 license with two-repo open-core architecture.

## Key Files
- **PROJECT_CONTEXT.md** — Canonical project context (stable, comprehensive). READ THIS FIRST.
- **EVOLUTION.md** — Permanent breadcrumb trail. Backup if this file resets.
- **DOCS.md** — Technical documentation
- **DOD.md** — Definition of Done checklist

## Critical Rules (Summary)
1. **After ANY Go code changes**: Run `go test ./go-server/... -count=1` before considering work done.
2. **After CSS changes**: Run `npx csso static/css/custom.css -o static/css/custom.min.css`
3. **Version bumps**: Update `AppVersion` in `go-server/internal/config/config.go`
4. **Build**: `./build.sh` compiles to `./dns-tool-server`; `main.py` is the gunicorn trampoline.
5. **CSP**: No inline onclick/onchange/style="". Use addEventListener in nonce'd script blocks.
6. **Safari**: Use showOverlay() for animated overlays — WebKit animation restart bug.
7. **SecurityTrails**: User-key-only. NEVER call automatically. 50 req/month hard limit.
8. **Reality Check**: Every claim must be backed by implemented code. Use "on the roadmap" for future items.
9. **Font Awesome**: WOFF2 subset only. Check CSS rule exists before using new icons.
10. **Stubs**: `_oss.go` files return safe non-nil defaults, never errors.
11. **Capitalization**: NIST/Chicago title case for all user-facing headings, badges, trust indicators. Never camelCase in UI copy.

## Authentication (v26.20.56–57)
- **Google OAuth 2.0 + PKCE** — Pure stdlib, no external OAuth libraries. Advanced Protection compatible.
- **Env vars**: `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `INITIAL_ADMIN_EMAIL` (all optional — app runs without them).
- **One-time admin bootstrap**: `INITIAL_ADMIN_EMAIL` grants admin only if zero admins exist in DB.
- **Security**: email_verified enforced, ID token claims validated, rate-limited /auth/*, no tokens stored, audit logging.
- **Nav**: "Sign In" (fa-key) in collapse menu; authenticated dropdown with fa-user-shield; admin badge fa-shield.
- **Route protection**: /export/json requires admin. All analysis remains no-login-required.

## SMTP Probe Infrastructure (v26.20.87)
- **Remote probe mode**: `SMTP_PROBE_MODE=remote` calls external probe API instead of local port 25.
- **Probe server**: `probe-us-01.dns-observe.com` — Python 3 API (`/opt/dns-probe/probe_api.py`), systemd unit `dns-probe.service`, Caddy reverse proxy.
- **Secrets**: `PROBE_API_URL`, `PROBE_SSH_HOST`, `PROBE_SSH_USER`, `PROBE_SSH_PRIVATE_KEY` (all configured).
- **API endpoints**: POST `/probe/smtp` (with `{"hosts": [...]}`) and GET `/health`.
- **Fallback**: If remote probe fails, falls back to local direct SMTP probing (`force` mode).
- **SSH access**: `ssh -i <key> root@probe-us-01.dns-observe.com` — key requires newline reformatting from secret storage.

## Engines
- **ICIE** — Intelligence Classification & Interpretation Engine (analysis logic)
- **ICAE** — Intelligence Confidence Audit Engine (accuracy tracking). Package: `go-server/internal/icae/`. DB tables: `ice_*` (legacy prefix, not renamed). Two layers per protocol: collection + analysis. Maturity: development → verified → consistent → gold → gold_master. 45 deterministic test cases.

## Repositories (GitHub Canonical, Codeberg Mirror)
- **Webapp**: `careyjames/DnsToolWeb` (GitHub, canonical) → `careybalboa/dns-tool-webapp` (Codeberg, read-only mirror)
- **Intel**: `careyjames/dnstool-intel` (GitHub, canonical) → `careybalboa/dns-tool-intel` (Codeberg, mirror)
- **CLI**: `careyjames/dns-tool-cli` (GitHub, canonical) → `careybalboa/dns-tool-cli` (Codeberg, read-only mirror)
- GitHub→Codeberg sync via `.github/workflows/mirror-codeberg.yml`. SonarCloud runs on GitHub (primary).

## Architecture Quick Reference
- **Build tags**: `//go:build intel` (private) / `//go:build !intel` (public OSS stubs)
- **12 stub files**: edge_cdn, saas_txt, infrastructure, providers, ip_investigation, manifest, posture_diff, ai_surface/{http,llms_txt,robots_txt,poisoning,scanner}
- **Intel repo sync (GitHub)**: `node scripts/github-intel-sync.mjs` — reads/writes `careyjames/dnstool-intel` via GitHub API (canonical).
- **Webapp sync (Codeberg)**: `node scripts/codeberg-webapp-sync.mjs` — reads/writes `careybalboa/dns-tool-webapp` via Forgejo API (mirror).
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
