# DNS Tool — Domain Security Intelligence Platform

[![License: BSL 1.1](https://img.shields.io/badge/License-BSL%201.1-blue.svg)](LICENSE)
[![SonarCloud](https://sonarcloud.io/api/project_badges/measure?project=careyjames_DnsToolWeb&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=careyjames_DnsToolWeb)

> **Decision-ready intelligence, not just DNS data.**

DNS Tool is an RFC-compliant OSINT platform for domain security analysis, producing intelligence reports covering email authentication (DMARC, SPF, DKIM), transport security (DANE, MTA-STS), and brand protection (BIMI, CAA).

**Live**: [dnstool.it-help.tech](https://dnstool.it-help.tech)

## What It Does

Enter a domain. Get a security intelligence report that answers questions like:

- **Can this domain be impersonated by email?** (DMARC/SPF/DKIM analysis)
- **Are spoofed emails rejected or quarantined?** (Policy enforcement)
- **Can attackers downgrade SMTP to intercept mail?** (MTA-STS/DANE)
- **Can DNS responses be tampered with in transit?** (DNSSEC chain validation)

Two report formats:
- **Engineer's DNS Intelligence Report** — technical detail for security teams
- **Executive's DNS Intelligence Brief** — board-ready summary for leadership

## Architecture

- **Go/Gin backend** with Bootstrap 5 dark theme frontend
- **ICIE** — Intelligence Classification & Interpretation Engine (analysis logic)
- **ICAE** — Intelligence Confidence Audit Engine (accuracy tracking)
- PostgreSQL database, TLP v2.0 classification

## Getting Started

```bash
./build.sh          # compile Go server
./dns-tool-server   # run on :5000
```

## Mirrors

This repository is the canonical source. A read-only mirror is maintained at [codeberg.org/careybalboa/dns-tool-webapp](https://codeberg.org/careybalboa/dns-tool-webapp).

## License

[Business Source License 1.1](LICENSE) — IT Help San Diego Inc.

The Licensed Work is © 2024–2025 Carey James Balboa / IT Help San Diego Inc. The Change Date is four years from each release. After the Change Date, the software converts to the GNU General Public License v2.0 or later.
