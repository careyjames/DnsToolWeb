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

Providers like Cloudflare, AWS Route53, Google Cloud DNS, Akamai, Azure, and NS1 offer DDoS protection, anycast networks, and 24/7 security monitoring. A domain on Cloudflare without DNSSEC may be MORE secure than a self-hosted domain with DNSSEC. These are tagged "Enterprise" in the results.

### Legacy Providers

Network Solutions, Bluehost, HostGator, and similar legacy providers are explicitly blocklisted to prevent false "Enterprise" tagging.

### Government Domains

Domains using .gov, .mil, and equivalent government TLDs operate under strict compliance frameworks with mandatory security requirements. These are recognized as "Government" tier with inherent trust.

### Self-Hosted Enterprise

Large organizations running their own NS infrastructure are detected by multiple nameservers matching the domain and recognized as capable of implementing alternative security.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string (e.g., `postgresql://user:pass@host/dbname`) |
| `SESSION_SECRET` | Yes | Session encryption key for CSRF protection |

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
main.py                        # Process trampoline (execs Go binary via os.execvp)
dns-tool-server                # Compiled Go binary
go-server/
  cmd/server/
    main.go                    # Entry point (Gin router, template setup, handlers)
  internal/
    config/                    # Configuration loading (env vars, defaults)
    analyzer/                  # DNS analysis engine
                               #   - orchestrator.go (concurrent lookups, result aggregation)
                               #   - spf.go, dkim.go, dmarc.go, dnssec.go, etc. (analyzers)
                               #   - infrastructure.go (enterprise provider detection, golden rules)
                               #   - posture.go (CVSS-aligned risk scoring)
                               #   - ai_surface/ (llms.txt detection, prompt injection)
                               #   - email header analysis, IP investigation
    handlers/                  # HTTP route handlers
                               #   - analysis.go (domain analysis, results page)
                               #   - email_header.go (paste/upload email headers)
                               #   - investigate.go (IP-to-domain, IP-to-ASN)
                               #   - history.go (historical analyses)
                               #   - export.go (JSON export)
    dnsclient/                 # DNS client with multi-resolver consensus
                               #   - Cloudflare, Google, Quad9, OpenDNS
                               #   - DoH fallback for censorship resistance
    db/                        # PostgreSQL database layer (pgx v5, sqlc)
    middleware/                # CSRF, rate limiting, SSRF hardening
    telemetry/                 # Caching (Redis-ready), metrics collection
    models/                    # Data structures
  templates/                   # Go html/template server-rendered pages
  static/                      # CSS (Bootstrap dark theme), JS, assets
```

## Key Features

### Email Security Analysis

- **SPF**: Record validity, lookup count, permissiveness, redirect= chain handling with loop detection
- **DKIM**: Common selectors, key strength, signature verification
- **DMARC**: Policy (none/quarantine/reject), alignment, external reporting authorization (DMARC ARF delegation)
- **MTA-STS**: Policy mode, MX host validation
- **TLS-RPT**: Reporting URI configuration
- **BIMI**: Logo URL, VMC certificate validation
- **Email Header Analyzer**: Paste or upload email headers for SPF/DKIM/DMARC verification, delivery route tracing, alignment checking, spoofing detection, base64/QP body decoding

### DNS Security

- **DNSSEC**: DS/DNSKEY presence, validation chain integrity
- **CAA**: Certificate authority restrictions
- **DANE/TLSA**: TLS certificate pinning records
- **NS Delegation**: Authoritative nameserver consistency

### Infrastructure & Provider Detection

- **Enterprise DNS**: Automatic detection of Cloudflare, AWS Route53, Google Cloud DNS, Akamai, Azure, NS1, and others with golden rule test coverage
- **Legacy Provider Blocklist**: Explicitly prevents false "Enterprise" tagging
- **Government Domains**: Recognition of .gov, .mil TLDs with inherent trust
- **Self-Hosted Enterprise**: Detection via multiple matching nameservers
- **Edge/CDN Detection**: Identifies CDN vs origin servers
- **HTTPS/SVCB Records**: HTTP/3 and service binding intelligence

### Advanced Analysis

- **AI Surface Scanner**: Detects llms.txt at both `/.well-known/` and root, AI crawler governance signals (robots.txt), CSS-hidden prompt injection artifacts
- **CT Subdomain Discovery**: Certificate Transparency logs for comprehensive subdomain enumeration (1h cache, append-only)
- **DNS History Timeline**: SecurityTrails API integration for historical DNS records (24h cache, 50 calls/month limit)
- **IP Investigation**: IP-to-domain reverse lookups, IP-to-ASN attribution via Team Cymru
- **OpenPhish Integration**: Phishing URL detection against live feeds
- **SMTP Transport Validation**: Live SMTP TLS verification with DNS-inferred fallback
- **SaaS TXT Footprint**: Extraction of SaaS provider indicators
- **CDS/CDNSKEY Detection**: Automation indicators for DNS delegation signer updates
- **SMIMEA/OPENPGPKEY**: Email encryption key discovery
- **security.txt Detection**: RFC 9116 security contact information

### Posture Scoring

Scores are aligned with CVSS methodology and categorized as:

- **Action Required**: Critical security gap
- **Monitoring**: Partial implementation, data collection in progress
- **Configured**: Best practices implemented
- **Not Configured**: Feature not in use

### Reporting & Export

- **Print/PDF Executive Report**: Professional print stylesheet with TLP:CLEAR classification, domain banner, colored sections, B&W laser-safe palette, controlled page breaks
- **JSON Export**: Machine-readable analysis results
- **Timestamp & Duration**: Every analysis includes creation time and execution duration

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

6. **Middleware Stack**:
   - **Recovery**: Graceful error handling with version reporting
   - **Request Context**: CSP nonce generation, CSRF token injection
   - **Security Headers**: HSTS, X-Content-Type-Options, X-Frame-Options, CSP
   - **CSRF Protection**: Token validation on POST requests
   - **Rate Limiting**: In-memory (Redis-ready for multi-worker deployments)
   - **SSRF Hardening**: Blocks private IP ranges in external requests

7. **Database**: PostgreSQL via `pgx` v5 for high performance. Queries generated by `sqlc` for type safety and SQL injection prevention.

## External Integrations

- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS (for consensus)
- **IANA RDAP**: Registry data lookups (24h cache due to rate limits)
- **ip-api.com**: Visitor IP-to-country lookups
- **Certificate Transparency (crt.sh)**: Subdomain discovery (1h cache)
- **SecurityTrails**: DNS history timeline (user-provided API key, no server-side storage)
- **Team Cymru**: DNS-based IP-to-ASN attribution
- **OpenPhish**: Phishing URL detection

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
- CT subdomain discovery with caching
- SecurityTrails DNS history integration
- IP Investigation with IP-to-ASN attribution
- Posture scoring with CVSS alignment
- Print/PDF executive reports
- OpenPhish integration
- SMTP TLS transport validation
- CSP with nonces for XSS protection
