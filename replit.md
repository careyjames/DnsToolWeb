# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records such as SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, and CAA, with automatic subdomain discovery. The tool aims to provide accurate, RFC-cited, and verifiable results, focusing on elevating domain security through actionable insights and serving as an educational authority.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application is implemented in Go using the Gin framework, having been rewritten from a Python/Flask codebase for improved performance and concurrency. The architecture follows an MVC-style separation. The legacy Python/Flask code is archived in `docs/legacy/` with full documentation in `docs/legacy/LEGACY_ARCHIVE.md` — it is not maintained or executed.

### Backend
- **Technology Stack**: Go with Gin web framework, `pgx` v5 for PostgreSQL, `sqlc` for type-safe query generation, and `miekg/dns` for all DNS queries.
- **Templates**: Go `html/template`.
- **Project Structure**: `go-server/cmd/server/` (entry point), `go-server/internal/` (config, db, handlers, middleware, models, templates, analyzer, dnsclient, telemetry, providers), `go-server/db/queries/`, `go-server/templates/`.
- **Key Features**: Multi-resolver consensus DNS client with DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator, CSRF middleware (HMAC-signed cookie tokens), rate limiting, SSRF hardening, and telemetry for provider health monitoring and RDAP caching.
- **Posture Evaluation**: Risk levels are CVSS-aligned (Critical, High, Medium, Low, Informational), derived from actual protocol states and providing comprehensive remediation guidance with RFC citations.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, comprehensive accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella (for consensus).
- **IANA RDAP**: For registry data lookups.
- **ip-api.com**: For IP-to-country lookups.
- **crt.sh**: For Certificate Transparency logs.

### Database
- **PostgreSQL**: The primary database for persistent storage.

## Development Operations

### Version Bump Process
The app version is defined in `go-server/internal/config/config.go` (the `AppVersion` field). To bump the version and get it live:

1. **Edit the version** in `go-server/internal/config/config.go`
2. **Rebuild the binary**: `go build -buildvcs=false -o /tmp/dns-tool-server ./go-server/cmd/server/`
3. **Swap the binary** (rename-swap because the running binary is locked):
   - `mv dns-tool-server dns-tool-server-old`
   - `mv /tmp/dns-tool-server dns-tool-server`
   - `rm dns-tool-server-old`
4. **Restart the workflow** to pick up the new binary

### Build Notes (Replit-specific)
- **Git lock issue**: `go build` in Replit triggers VCS stamping which fails due to `.git/index.lock`. **Always** use the `-buildvcs=false` flag.
- **Binary replacement**: A running binary cannot be overwritten ("Text file busy"). Always build to `/tmp/` first, then rename-swap as described above.
- **Workflow trampoline**: The `.replit` workflow command uses `gunicorn ... main:app` (legacy config). The `main.py` file is a process trampoline that immediately replaces itself with `./dns-tool-server` via `os.execvp`. The Go binary is what actually runs on port 5000. This is a workaround because the `.replit` file cannot be directly edited by the agent.
- **`run.sh`**: Available as a convenience script that builds fresh and runs. Can be used for manual testing but is not invoked by the workflow.
- **`.replit` file**: Cannot be directly edited by the agent. The workflow command references gunicorn but the actual server is the Go binary (via the main.py trampoline).
- **Deployment**: The `.replit` deployment section has its own build command (`CGO_ENABLED=0 go build -o dns-tool-server ./go-server/cmd/server/`) and run command (`./dns-tool-server`) which handle production builds automatically.

### Feature Parity Manifest
The living feature parity manifest is at `go-server/internal/analyzer/manifest.go` with automated tests in `manifest_test.go`. These tests enforce that every required schema key is present in the orchestrator output. When adding or removing analysis features, update the manifest — the tests will fail if the manifest and orchestrator are out of sync. The feature inventory documentation is at `docs/FEATURE_INVENTORY.md`.

### Risk Level Labels
Posture risk levels follow CVSS-aligned semantics: **Informational** (best) → **Low Risk** → **Medium Risk** → **High Risk** → **Critical Risk** (worst). Legacy stored values (bare "Low", "Medium", etc.) are normalized at display time in `NormalizeResults()` in `go-server/internal/handlers/helpers.go`. Remediation severity labels (Critical/High/Medium/Low) are separate from posture states.