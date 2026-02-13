# DNS Tool Intelligence Module

**PROPRIETARY — ALL RIGHTS RESERVED**

This repository contains the analysis intelligence layer for [DNS Tool](https://dnstool.it-help.tech) — the interpretation engine that transforms raw DNS data into actionable security intelligence.

## What's Here

| Directory | Purpose | Why It's Proprietary |
|-----------|---------|---------------------|
| `scoring/` | Posture scoring & CVSS-aligned risk levels | 25 years of field expertise encoded in scoring logic |
| `remediation/` | RFC-aligned remediation guidance | Nuanced best practices (SPF ~all vs -all, DANE+MTA-STS, etc.) |
| `providers/` | Provider fingerprinting & detection | Infrastructure, edge/CDN, SaaS TXT, email management providers |
| `golden_rules/` | Analysis integrity test definitions | The expected behavior standard that defines quality |
| `commands/` | Verification command generation & manifest | "Verify It Yourself" command equivalence system |

## Relationship to dnstoolweb

The public repository ([dnstoolweb](https://github.com/...)) contains the infrastructure:
- DNS client (miekg/dns) — how we query
- HTTP handlers, middleware, templates — how we serve
- Database layer — how we store
- Protocol analyzers — how we parse DNS records

This repository contains the intelligence:
- How we **score** what we find
- How we **advise** what to fix
- How we **fingerprint** who's behind it
- How we **verify** our own accuracy

The transport layer is transparent. The interpretation layer is the value.

## License

Copyright (c) 2024-2026 IT Help San Diego Inc. All rights reserved.
See [LICENSE](LICENSE) for full terms.
