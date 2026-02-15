# DNS Tool — Documentation

## Overview

A comprehensive DNS intelligence and OSINT platform for domain security analysis. Built in Go with the Gin framework. Designed for three audiences:

- **Board-level executives**: Quick security posture at a glance
- **IT professionals**: Actionable email security recommendations
- **DNS specialists**: Deep technical record analysis

## Philosophy: No Proprietary Magic

Every conclusion must be independently verifiable using standard commands. The tool operates with strict adherence to RFC standards and observation-based language—never making definitive claims beyond what the data shows.

### Core Principles

1. **Fresh Data**: DNS records are always fetched live (TTL=0, no caching) because domains in trouble often have rapidly changing DNS records, and security incidents require up-to-the-second accuracy.

2. **Verifiable Results**: All analyses include equivalent shell commands users can run themselves for verification.

3. **Observation-Based Language**: Not "Is email encrypted?" but "Transport encryption observed?"

4. **Defensible Caches Only**:
   - RDAP registry data (24h) — registrar information rarely changes
   - DNS History (24h) — prevents excessive API calls to SecurityTrails
   - CT subdomains (1h) — append-only historical data
   - RFC metadata (24h) — reference data that updates slowly

## Symbiotic Security

Traditional DNS security tools treat DNSSEC as the only valid security measure, penalizing domains that skip it. This tool recognizes that enterprises implement security through multiple layers:

### Enterprise DNS Providers

Major cloud and infrastructure DNS providers offer DDoS protection, anycast networks, and 24/7 security monitoring. A domain on a top-tier provider without DNSSEC may be MORE secure than a self-hosted domain with DNSSEC. These are tagged "Enterprise" in the results.

### Legacy Providers

Certain legacy DNS providers are explicitly blocklisted to prevent false "Enterprise" tagging.

### Government Domains

Domains using .gov, .mil, and equivalent government TLDs operate under strict compliance frameworks with mandatory security requirements. These are recognized as "Government" tier with inherent trust.

### Self-Hosted Enterprise

Large organizations running their own NS infrastructure are detected by multiple nameservers matching the domain and recognized as capable of implementing alternative security.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string (e.g., `postgresql://user:pass@host/dbname`) |
| `SESSION_SECRET` | Yes | Session encryption key for CSRF protection |
| `PORT` | No | HTTP listen port (default: `5000`) |

## Running the Application

The workflow executes:

```bash
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

This command imports `main.py`, which contains an `os.execvp` trampoline. The trampoline immediately replaces the gunicorn process image with the compiled Go binary (`./dns-tool-server`), so gunicorn never actually starts. The Go binary takes over and binds to port 5000.

## Building

Rebuild the Go binary after any changes to `.go` files:

```bash
cd go-server && GIT_DIR=/dev/null go build -buildvcs=false -o /tmp/dns-tool-new ./cmd/server/
mv /tmp/dns-tool-new dns-tool-server-new && mv dns-tool-server-new dns-tool-server
```

Then restart the "Start application" workflow to reload the binary.

## Running Tests

```bash
cd go-server && go test ./... -v
```

Tests include unit tests, integration tests, golden rules (golden_rules_test.go), and behavioral contract tests.

## Architecture

```
main.py                    # Process trampoline (execs Go binary)
dns-tool-server            # Compiled Go binary
go-server/
  cmd/server/main.go       # Entry point
  internal/
    analyzer/              # DNS analysis engine
    handlers/              # HTTP route handlers
    dnsclient/             # Multi-resolver DNS client
    db/                    # PostgreSQL (pgx v5, sqlc)
    middleware/            # Security middleware
    telemetry/             # Caching, metrics
  templates/               # Server-rendered HTML
  static/                  # CSS, JS, assets
```

## Key Features

### Email Security Analysis
SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI — RFC-compliant parsing and validation for all major email authentication protocols. Includes an Email Header Analyzer for pasting or uploading raw headers to verify authentication results and trace delivery routes.

### DNS Security
DNSSEC chain-of-trust verification, CAA certificate authority restrictions, DANE/TLSA certificate pinning, NS delegation consistency.

### Infrastructure Detection
Automatic enterprise DNS provider recognition, government domain tier classification, edge/CDN detection, SMTP transport validation.

### Intelligence
AI Surface Scanner, CT subdomain discovery, DNS history timeline (SecurityTrails), IP Intelligence, phishing detection.

### Exposure Scanning
Two-tier approach to web security exposure detection:
- **Public Exposure Checks** (always-on): Scans publicly accessible page source and linked JavaScript for exposed secrets, API keys, and credentials.
- **Expanded Exposure Checks** (opt-in): Probes 8 well-known misconfiguration paths (/.env, /.git/config, /.git/HEAD, /.DS_Store, /server-status, /server-info, /wp-config.php.bak, /phpinfo.php) with content validation. Sequential requests with 200ms delays.

**Note**: These are informational reconnaissance checks — not PCI DSS ASV scans, penetration tests, or compliance attestations.

### Posture Scoring
CVSS-aligned risk assessment with actionable remediation recommendations.

### Reporting
Dual intelligence products: Engineer's DNS Intelligence Report (comprehensive technical detail) and Executive's DNS Intelligence Brief (concise board-ready summary with security scorecard, risk posture, and priority actions). Both use the same live analysis data — different formats for different audiences. Naming follows IC conventions: "Report" = comprehensive, "Brief" = concise decision-maker version. Configurable TLP classification (default: TLP:AMBER, aligned with CISA Cyber Hygiene practice) with TLP:GREEN and TLP:CLEAR options. JSON export for programmatic consumption.

### Report Integrity
Every analysis generates a SHA-256 integrity hash binding domain, analysis ID, timestamp, tool version, and canonicalized results data. Header preview format: `SHA-256: c82f✱✱✱✱ Report Integrity ↓` (4 hex chars + 4 star masks + anchor link to full hash section). Copy-to-clipboard support. Distinct from posture hash (drift detection).

## Rate Limiting & Abuse Prevention

| Protection | Window | Purpose |
|------------|--------|---------|
| **Rate Limit** | 8 requests/minute per IP | Prevents abuse and network overload |
| **Anti-Repeat** | 15 seconds per domain | Prevents accidental double-clicks during DNS editing |

**Why 15 seconds for anti-repeat?** A sysadmin editing DNS in a registrar panel and switching tabs typically needs 20+ seconds. 15 seconds blocks rapid re-clicks that waste network resources without blocking legitimate edits.

**Note**: There is no "Force Fresh" toggle—every analysis is fresh. The anti-repeat protection is purely double-click prevention, not caching.

## Performance

| Operation | Expected Time | Notes |
|-----------|---------------|-------|
| Domain analysis | 5-30 seconds | Depends on DNS response times and number of queries |
| Page load | < 100ms | Static assets cached aggressively with immutable flags |

## Key Design Decisions

1. **Server-Side Rendering**: All pages rendered server-side using Go `html/template`. No client-side API calls. Better SEO, simpler deployment, inherent CSRF protection.

2. **Concurrent DNS Lookups**: Goroutines enable parallel queries across multiple resolvers with rapid aggregation.

3. **Multi-Resolver Consensus**: Queries Cloudflare, Google, Quad9, and OpenDNS. Consensus-based results reduce resolver-specific anomalies.

4. **CSP with Nonces**: Content Security Policy headers include per-request nonces for inline scripts, blocking XSS attacks while allowing necessary inline code.

5. **Dark Theme UI**: Bootstrap dark theme with custom CSS. Eye-friendly, modern, professional appearance.

6. **Security Middleware**: CSRF, rate limiting, SSRF hardening, security headers, CSP nonces.

7. **Database**: PostgreSQL via `pgx` v5. Queries generated by `sqlc` for type safety.

## Caching Strategy

| Cache Target | TTL | Reason |
|--------------|-----|--------|
| DNS queries | TTL=0 (none) | Live data for security incidents |
| RDAP data | 24h | Registrar info rarely changes; prevents rate-limit issues |
| DNS History | 24h | SecurityTrails API quota protection (50 calls/month limit) |
| CT subdomains | 1h | Append-only data, minimal changes |
| RFC metadata | 24h | Reference data, infrequent updates |

## Database

PostgreSQL is the primary persistent store. Database schema is defined in `go-server/db/schema/schema.sql`. Queries are written in `go-server/db/queries/` and generated by `sqlc` into type-safe Go code in `go-server/internal/dbq/`.

- **Development and production use separate databases** (platform change, Dec 2025)
- Development database: Test scans only
- Production database: Real user scan history

## Troubleshooting

### Analysis Times Out

Some DNS servers respond slowly. Partial results are shown with a warning banner. Re-analyze to retry.

### RDAP Lookup Fails

Registry may be rate-limiting. Falls back to WHOIS. Cached data used if available.

### DNSSEC Shows "Unsigned" for Known-Secure Domain

Domain likely uses an enterprise DNS provider. Check the "DNS Tampering" scorecard—it should show "Enterprise". This is intentional per the symbiotic security philosophy.

### No MX Records Found

Domain may be intentionally non-mail. Check SPF for `v=spf1 -all` pattern. We detect and explain "no-mail domains".

### Rate Limit Exceeded

Maximum 8 requests per minute per IP. Wait 60 seconds and retry.

## Version History

### v26.4.30+

- Go/Gin rewrite (complete backend replacement)
- Concurrent DNS analyzer with goroutines
- Enterprise provider golden rules with test coverage
- CSRF protection via middleware
- In-memory rate limiting (Redis-ready)
- Server-rendered Go templates
- Multi-resolver consensus (Cloudflare, Google, Quad9, OpenDNS)
- AI Surface Scanner with prompt injection detection
- Email Header Analyzer with RFC parsing
- Three-layer subdomain discovery (CT logs + wildcard detection + UDP DNS probing) with caching
- SecurityTrails DNS history integration
- IP Intelligence with IP-to-ASN attribution
- Posture scoring with CVSS alignment
- Dual intelligence products (Engineer's DNS Intelligence Report + Executive's DNS Intelligence Brief)
- OpenPhish integration
- Public exposure checks (secret scanning in page source)
- Expanded exposure checks (opt-in well-known path probing)
- Report integrity hash (SHA-256 with header preview)
- Posture drift detection foundation
- SMTP TLS transport validation
- CSP with nonces for XSS protection
