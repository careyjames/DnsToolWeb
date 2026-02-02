# DNS Analysis Tool - Documentation

## Overview

A comprehensive DNS intelligence and OSINT platform that provides domain security analysis for three audiences:
- **Board-level executives**: Quick security posture at a glance
- **IT professionals**: Actionable email security recommendations
- **DNS specialists**: Deep technical record analysis

## Philosophy: Symbiotic Security

Traditional DNS security tools often treat DNSSEC as the only valid security measure, penalizing domains that don't implement it. Our tool takes a more nuanced **"symbiotic security"** approach:

### Core Principle
> Not all security looks the same. Enterprise providers, government entities, and modern cloud platforms implement security through multiple layers, not just DNSSEC.

### What This Means

1. **Enterprise DNS Providers** (Cloudflare, AWS Route53, Google Cloud DNS, Akamai, Azure)
   - These providers offer DDoS protection, anycast networks, and 24/7 security monitoring
   - A domain on Cloudflare without DNSSEC may be MORE secure than a self-hosted domain with DNSSEC
   - We detect enterprise providers and explain their security measures

2. **Government Domains** (.gov, .mil, .gov.uk, etc.)
   - Government TLDs have mandatory security requirements
   - They operate under strict compliance frameworks
   - We recognize these as "Government" tier with inherent trust

3. **Self-Hosted Enterprise**
   - Large organizations running their own NS infrastructure
   - Detected by multiple nameservers matching the domain
   - Recognized as capable of implementing alternative security

### Fresh Data Philosophy

**DNS records are ALWAYS fetched fresh** - we never cache DNS lookups because:
- Domains in trouble often have rapidly changing DNS
- Security incidents require up-to-the-second accuracy
- Misconfiguration detection needs current state

Only RDAP registry data is cached (6 hours) since registrar information rarely changes.

### Rate Limiting & Anti-Repeat Protection

To prevent abuse while honoring the "fresh data" promise:

| Protection | Window | Purpose |
|------------|--------|---------|
| **Rate Limit** | 8 requests/minute per IP | Prevents abuse and network overload |
| **Anti-Repeat** | 15 seconds per domain | Prevents accidental double-clicks |

**Why 15 seconds for anti-repeat?**
- A human editing DNS in GoDaddy/Cloudflare and switching tabs typically takes 20+ seconds
- 15 seconds is short enough that real edits won't be blocked
- Long enough to prevent rapid re-clicks that waste network resources

**Note**: There is no "Force Fresh" toggle - every analysis is fresh. The anti-repeat is purely double-click protection, not caching.

**Deployment Note**: Rate limiting uses in-memory storage, which works correctly with a single Gunicorn worker (the Replit default). If running multiple workers, consider Redis-backed rate limiting.

---

## Operator Guide

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SESSION_SECRET` | Yes | Flask session encryption key |

### Running the Application

```bash
# Start the application (port 5000)
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

### Running Tests

```bash
# Run all tests (unit + integration)
python -m pytest tests/ -v

# Run only unit tests
python -m pytest tests/test_dns_analyzer.py -v

# Run only integration tests
python -m pytest tests/test_integration.py -v
```

### Expected Performance

| Operation | Expected Time | Notes |
|-----------|---------------|-------|
| Domain analysis | 2-8 seconds | Depends on DNS response times |
| RDAP lookup | 0.5-2 seconds | May be cached (6h TTL) |
| Page load (cached) | < 100ms | Static assets served directly |

### Timeout Behavior

Each analysis section has its own timeout handling:
- Global analysis timeout: 20 seconds
- Individual section timeout: 2-3 seconds per external call
- Partial results are displayed if some sections time out
- Failed sections show warning banners on the results page

### Rate Limits

External services have rate limits we respect:
- RDAP registries: Cached for 6 hours to avoid hammering
- DNS resolvers (Cloudflare 1.1.1.1): No practical limit
- SMTP verification: Disabled (port 25 blocked)

---

## Security Features Analyzed

### Email Security

| Feature | What We Check |
|---------|---------------|
| **SPF** | Record validity, lookup count, permissiveness |
| **DMARC** | Policy (none/quarantine/reject), alignment |
| **DKIM** | Common selectors, key strength |
| **MTA-STS** | Policy mode, MX hosts |
| **TLS-RPT** | Reporting URI configuration |
| **BIMI** | Logo URL, VMC certificate validation |

### DNS Security

| Feature | What We Check |
|---------|---------------|
| **DNSSEC** | DS/DNSKEY presence, validation chain |
| **CAA** | Certificate authority restrictions |
| **NS Delegation** | Authoritative nameserver consistency |

### Infrastructure Detection

| Tier | Detection Method | Meaning |
|------|------------------|---------|
| **Enterprise** | Nameserver keywords (cloudflare, awsdns, etc.) | Professional DNS hosting |
| **Government** | TLD suffix (.gov, .mil, etc.) | Policy-based security |
| **Self-Hosted Enterprise** | Multiple NS matching domain | Large organization |
| **Standard** | None of the above | Typical hosting |

---

## Scorecard Interpretation

### Email Spoofing
- **Protected**: SPF + DMARC with reject/quarantine policy
- **Monitoring**: SPF + DMARC with p=none (collecting data)
- **Partial**: Only SPF or only DMARC configured
- **Vulnerable**: Neither configured

### Brand Impersonation
- **Protected**: BIMI with valid VMC certificate
- **Basic**: BIMI logo without VMC
- **Not Setup**: No BIMI record

### DNS Tampering
- **Protected**: DNSSEC enabled and valid
- **Enterprise**: Enterprise DNS provider (alternative security)
- **Unsigned**: No DNSSEC, standard hosting

### Certificate Control
- **Configured**: CAA records restrict certificate issuers
- **Open**: Any CA can issue certificates

---

## Troubleshooting

### Common Issues

**Analysis times out**
- Some DNS servers respond slowly
- Partial results are shown with warning banner
- Re-analyze to try again

**RDAP lookup fails**
- Registry may be rate-limiting
- Falls back to WHOIS
- Cached data used if available

**DNSSEC shows "unsigned" for known-secure domain**
- Domain uses enterprise DNS provider
- Check "DNS Tampering" scorecard - should show "Enterprise"
- This is intentional per our symbiotic security philosophy

**No MX records found**
- Domain may be intentionally non-mail
- Check SPF for "v=spf1 -all" pattern
- We detect and explain "no-mail domains"

---

## Architecture

```
main.py           # Entry point (imports app)
app.py            # Flask routes, database models, CSP
dns_analyzer.py   # Core DNS analysis engine
dns_types.py      # Typed dataclasses for results
templates/        # Jinja2 HTML templates
static/           # CSS, JS, assets
tests/            # Unit and integration tests
```

### Key Design Decisions

1. **Server-side rendering**: No client-side API calls, better SEO
2. **Parallel DNS lookups**: ThreadPoolExecutor for speed
3. **CSP with nonces**: Score 130, protects against XSS
4. **Dark theme**: Modern, eye-friendly UI

---

## Version History

### v26.4.30 (Current)
- Fixed Re-analyze button race condition
- Fixed Brand Impersonation scorecard VMC detection
- Added analysis timestamp and duration display
- Added partial failure banners
- Increased RDAP cache TTL to 6 hours
- Added 53 unit + integration tests
