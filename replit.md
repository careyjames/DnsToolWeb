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
- **Key Features**: Multi-resolver consensus DNS client with DoH fallback, CT subdomain discovery, posture scoring, concurrent orchestrator, SMTP transport verification (STARTTLS/TLS/cipher/cert with DNS-inferred fallback), CSRF middleware (HMAC-signed cookie tokens), rate limiting, SSRF hardening, telemetry for provider health monitoring and RDAP caching, confidence labeling (Observed/Inferred/Third-party), and "Verify It Yourself" command equivalence appendix.
- **Confidence Taxonomy**: Three-tier attribution labels (Observed/Inferred/Third-party) in `go-server/internal/analyzer/confidence.go`. All heuristic attributions (provider detection, registrar, hosting, government entity) include confidence metadata.
- **Verification Commands**: `go-server/internal/analyzer/commands.go` generates domain-specific terminal commands (dig, openssl, curl) replicating every analysis step. Shown in results page (collapsible section) and print/PDF reports (appendix).
- **Changelog**: `go-server/internal/handlers/changelog.go` maintains a structured changelog displayed as "What's New" cards on the homepage.
- **Posture Evaluation**: Risk levels are CVSS-aligned (Critical, High, Medium, Low, Informational), derived from actual protocol states and providing comprehensive remediation guidance with RFC citations.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, comprehensive accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare.
- **Print/PDF Report**: Executive-grade print stylesheet (`@media print` in `static/css/custom.css`) with TLP:CLEAR classification, domain banner focal point, colored section headers (navy/teal alternating), B&W laser-safe color palette, gradient accent bars, zebra-striped tables, and controlled page breaks. Print-only markup in `go-server/templates/results.html` (`.print-report-header`, `.print-domain-banner`, `.print-report-footer`). Full feature details in `docs/FEATURE_INVENTORY.md` §6.1.1.

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

### DKIM Assessment Logic
DKIM selectors are not enumerable via DNS (RFC 6376 §3.6.2.1). The tool checks ~35 common selectors but cannot confirm DKIM absence. The posture system distinguishes three states:
- **Confirmed found** (`dkimOK`/`dkimProvider`): DKIM selectors discovered with valid keys, or primary provider is known to use DKIM (e.g., Google Workspace, Microsoft 365). Classified as "configured."
- **Inconclusive** (`dkimPartial`): No selectors found but provider is unknown — DKIM may exist with custom/rotating selectors. Classified as "monitoring" with Low-severity "Verify" remediation, not "absent."
- **No-mail domain**: Domains with null MX + SPF -all skip DKIM remediation entirely. DKIM signing is not applicable for domains that don't send email.
- **Confirmed absent**: No selectors found, no known provider, domain sends mail. Classified as "absent" with High-severity "Configure" remediation.

### SonarCloud Code Quality
- **Configuration**: `sonar-project.properties` at project root. Excludes `docs/legacy/**`, `go-server/db/schema/**`, and `templates/**`. PL/SQL VARCHAR2 rule (false positive for PostgreSQL) is suppressed for `.sql` files.
- **SONAR_TOKEN**: Stored as an encrypted Replit secret. Used for API-based quality gate checks.
- **Cognitive Complexity**: All production functions refactored below SonarCloud's threshold of 15. Helper extraction pattern used throughout handlers, dnsclient, and posture analyzer.
- **Risk Level Constants**: `riskLow`, `riskMedium`, `riskHigh`, `riskCritical` defined in `go-server/internal/analyzer/posture.go`.

### Template Comparison Safety
All six Go template comparison operators (`eq`, `ne`, `gt`, `lt`, `ge`, `le`) are overridden in `go-server/internal/templates/funcs.go` with type-safe versions that use `toFloat64()` for cross-type numeric comparisons. This prevents panics when comparing `float64` values (from `mapGetFloat`) with integer literals in templates. Template authors can safely write `eq $floatVar 0` without worrying about type mismatches. The custom `eq` preserves Go's variadic semantics (`eq arg1 arg2 arg3...` means `arg1==arg2 || arg1==arg3 || ...`).

### Analysis Integrity Standard
The tool's analysis logic — posture scoring, remediation recommendations, risk levels, and provider detection — must produce results that any RFC-literate security engineer, enterprise DNS engineer, or enterprise email infrastructure professional would independently reach the same conclusion reviewing the same data. This is the bar: convergent agreement across RFC standards bodies, enterprise security teams, and industry best practices from as many authoritative angles as possible. Every rating must be scientifically defensible and honest. Never inflate severity to appear thorough, never downplay to avoid attention. The golden rules test suite (`go-server/internal/analyzer/golden_rules_test.go`, 41 cases) is the automated regression guard protecting this standard.

### Remediation Best Practice Logic (Feb 2026)
The remediation engine follows strict RFC-aligned best practices with nuanced, context-aware recommendations:

**SPF ~all vs -all**: Per RFC 7489 §10.1, ~all (softfail) is the industry-standard best practice when DKIM is present, because DMARC evaluates both SPF and DKIM alignment. The tool only recommends upgrading to -all when DKIM is absent and SPF is the sole line of defense. SPF +all is flagged as Critical (anyone can spoof), ?all as High (no protection).

**SPF Lookup Count**: Exceeding 10 DNS lookups causes PermError (RFC 7208 §4.6.4), flagged as Medium severity.

**DMARC Reporting**: Missing rua= tag is flagged as Medium severity — without aggregate reporting, domain owners cannot monitor authentication results.

**DKIM Key Strength**: 1024-bit RSA keys are flagged as Medium severity with upgrade recommendation to 2048-bit (RFC 8301 §3.2). Third-party-only DKIM (no primary provider DKIM) also flagged.

**DNSSEC Broken Chain**: DNSKEY without DS at registrar is Critical — signatures exist but cannot be validated.

**DANE without DNSSEC**: TLSA records without DNSSEC are flagged as High — DANE requires DNSSEC to function (RFC 7672 §2.2). Conversely, if DNSSEC is present but DANE is not, a Low-severity recommendation suggests deploying DANE.

**CAA**: Absence is Low severity (advisory only). Not included in the posture "Recommended" summary to avoid overstating importance.

**Posture Summary Categories**: "Action Required" (red) for security-critical issues (SPF +all, broken DNSSEC). "Monitoring" (yellow-green) for deliberate monitoring states. "Configured" (green) for working protocols. "Not Configured" (grey) for absent protocols. The yellow "Recommended" section is reserved for genuinely actionable items — SPF ~all and CAA absence are NOT included here when the domain has proper DKIM/DMARC.