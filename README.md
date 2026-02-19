<p align="center">
  <img src="static/images/owl-of-athena.svg" alt="DNS Tool — Owl of Athena" width="120">
</p>

<h1 align="center">DNS Tool</h1>

<p align="center">
  <strong>Domain Security Intelligence Platform</strong><br>
  RFC-compliant OSINT analysis for email authentication, transport security, and brand protection.
</p>

<p align="center">
  <a href="https://github.com/careyjames/DnsToolWeb/releases"><img src="https://img.shields.io/badge/version-26.20.74-blue?style=flat-square" alt="Version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-BUSL--1.1-orange?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/Go-1.23-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/PostgreSQL-15+-336791?style=flat-square&logo=postgresql" alt="PostgreSQL">
  <img src="https://img.shields.io/badge/RFC--cited-7489%20%C2%B7%206376%20%C2%B7%207208-green?style=flat-square" alt="RFC Cited">
</p>

<p align="center">
  <a href="https://dnstool.it-help.tech">Live Demo</a> &middot;
  <a href="docs/architecture/SYSTEM_ARCHITECTURE.md">Architecture</a> &middot;
  <a href="DOCS.md">Technical Docs</a> &middot;
  <a href="docs/FEATURE_INVENTORY.md">Feature Inventory</a>
</p>

---

## What It Does

DNS Tool produces two intelligence products from a single domain scan:

| Report | Audience | Focus |
|--------|----------|-------|
| **Engineer's DNS Intelligence Report** | Security engineers, sysadmins | Full protocol analysis with RFC citations, verification commands, and remediation steps |
| **Executive's DNS Intelligence Brief** | CISOs, board members, compliance | TLP-rated risk summary in plain language with action items |

Every finding is backed by a specific RFC section, verification command, or DNS record — never opinions.

## Core Capabilities

### Email Security Triad
- **SPF** — Record parsing, mechanism analysis, lookup counting (RFC 7208)
- **DMARC** — Policy evaluation, alignment mode, aggregate/forensic reporting (RFC 7489)
- **DKIM** — Selector discovery, key strength validation, state machine analysis (RFC 6376)

### Transport Security
- **DANE/TLSA** — Certificate association validation (RFC 6698)
- **MTA-STS** — Policy fetch and mode evaluation (RFC 8461)
- **TLS-RPT** — Reporting endpoint detection (RFC 8460)
- **STARTTLS** — Live SMTP probe with certificate inspection

### Brand Protection
- **BIMI** — Brand indicator and VMC detection (RFC 9495)
- **CAA** — Certificate authority authorization analysis (RFC 8659)
- **Brand Impersonation Verdict** — 8-branch decision matrix combining DMARC + BIMI + CAA

### Infrastructure Intelligence
- **Subdomain Discovery** — Certificate Transparency + DNS probing pipeline
- **DNSSEC** — Chain validation and algorithm assessment (RFC 4033)
- **NS Delegation** — Nameserver health and consistency checks
- **AI Surface** — robots.txt AI crawler directives, llms.txt detection, poisoning indicators

### Privacy Controls
Three analysis modes protect user-provided intelligence:

| Mode | Trigger | Persistence |
|------|---------|-------------|
| **Public** | No novel selectors | Full — appears in history |
| **Private** | Authenticated + novel selectors | Persisted with privacy flag |
| **Ephemeral** | Anonymous + novel selectors | Not persisted — shown once |

Novel selectors are detected by checking against 81+ known defaults. Common selectors like `google`, `selector1`, `k1` never trigger privacy mode.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                  Go/Gin Server                   │
├────────────────┬───────────────┬─────────────────┤
│   ICIE Engine  │  ICAE Engine  │    Handlers     │
│  (Analysis)    │  (Audit)      │  (HTTP/Auth)    │
├────────────────┴───────────────┴─────────────────┤
│          DNS Client (miekg/dns · UDP)            │
├──────────────────────────────────────────────────┤
│         PostgreSQL · Bootstrap Dark Theme        │
└──────────────────────────────────────────────────┘
```

**ICIE** — Intelligence Classification & Interpretation Engine. Orchestrates concurrent DNS collection, protocol analysis, and verdict generation across 12+ protocol analyzers.

**ICAE** — Intelligence Confidence Audit Engine. 45 deterministic test cases across 5 protocol families validate analysis accuracy. Maturity progression: development → verified → consistent → gold → master gold.

Two-repo open-core model: public stubs compile cleanly without the private intelligence module (provider databases, scoring algorithms, remediation engine). Build tags (`//go:build intel` vs `!intel`) control which implementation compiles.

See [System Architecture Diagrams](docs/architecture/SYSTEM_ARCHITECTURE.md) for detailed Mermaid diagrams of the request lifecycle, engine internals, verdict chain, and package dependencies.

## Self-Auditing

DNS Tool audits its own accuracy. The ICAE runs 45 test cases covering:

| Protocol Family | Cases | What It Validates |
|----------------|-------|-------------------|
| SPF Analysis | 8 | Hard/soft fail, lookup limits, redirects, multiple records |
| DMARC Analysis | 12 | Policy levels, alignment, subdomain policy, percentage ramp |
| Transport Security | 8 | DANE, MTA-STS, combined presence, STARTTLS-only |
| Posture Classification | 9 | No-mail, protected, partial, at-risk, exposed, unknown |
| Brand Impersonation | 8 | Full 8-branch matrix from protected to exposed |

Every release runs the full suite. Results are stored and tracked over time with protocol-level maturity scoring.

## Quick Start

### Prerequisites
- Go 1.23+
- PostgreSQL 15+

### Build and Run

```bash
# Clone
git clone https://github.com/careyjames/DnsToolWeb.git
cd DnsToolWeb

# Set environment
export DATABASE_URL="postgresql://user:pass@localhost:5432/dnstool"
export SESSION_SECRET="your-secret-key"

# Build
./build.sh

# Run (binds to port 5000)
./dns-tool-server
```

### Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `SESSION_SECRET` | Yes | Session encryption key |
| `GOOGLE_CLIENT_ID` | No | Google OAuth 2.0 client ID |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth 2.0 client secret |
| `INITIAL_ADMIN_EMAIL` | No | Bootstrap admin (one-time, only if zero admins exist) |

The application runs fully without authentication configured — all analysis features work without login.

## Project Structure

```
go-server/
├── cmd/server/          # Entry point
├── internal/
│   ├── analyzer/        # ICIE — protocol analyzers + orchestrator
│   │   └── ai_surface/  # AI governance detection
│   ├── config/          # Application configuration
│   ├── db/              # Database connection
│   ├── dbq/             # Generated SQL queries (sqlc)
│   ├── dnsclient/       # DNS resolution (miekg/dns)
│   ├── handlers/        # HTTP handlers + auth
│   ├── icae/            # ICAE — accuracy audit engine
│   ├── middleware/       # CSP, CSRF, rate limiting
│   ├── models/          # Domain models
│   ├── providers/       # Provider detection interface
│   ├── telemetry/       # Logging + metrics
│   └── templates/       # Go HTML templates
├── queries/             # SQL query definitions
└── migrations/          # Database migrations
static/                  # CSS, JS, fonts, images
docs/                    # Architecture diagrams, feature inventory
```

## Standards and Citations

Analysis references these RFCs directly in findings:

| Protocol | RFC | Standard |
|----------|-----|----------|
| SPF | 7208 | Sender Policy Framework |
| DKIM | 6376 | DomainKeys Identified Mail |
| DMARC | 7489 | Domain-based Message Authentication |
| DANE | 6698 | DNS-Based Authentication of Named Entities |
| DNSSEC | 4033, 4034, 4035 | DNS Security Extensions |
| MTA-STS | 8461 | SMTP MTA Strict Transport Security |
| TLS-RPT | 8460 | SMTP TLS Reporting |
| BIMI | 9495 | Brand Indicators for Message Identification |
| CAA | 8659 | Certificate Authority Authorization |

Classification follows [FIRST TLP v2.0](https://www.first.org/tlp/), default TLP:AMBER.

## License

[Business Source License 1.1](LICENSE) — IT Help San Diego Inc.

You may use this software freely, including for production use, provided you do not offer it to third parties as a competitive DNS security audit service. See the [LICENSE](LICENSE) file for the complete terms and Additional Use Grant.
