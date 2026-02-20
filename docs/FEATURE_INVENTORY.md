# DNS Tool — Feature Overview

**Last Updated:** February 17, 2026 (v26.19.23)
**Implementation:** Go/Gin

---

## Purpose

This document provides a high-level overview of the DNS Tool's OSINT-based
domain security analysis capabilities for public reference. All data sources
are open-source intelligence — publicly available DNS records, certificate
transparency logs, RDAP registrar data, and web resources.

---

## Core DNS Security Analysis

The tool performs RFC-compliant parsing and validation of these protocols:

- **SPF Analysis** (RFC 7208) — mechanism parsing, lookup counting, permissiveness evaluation
- **DMARC Analysis** (RFC 7489) — policy parsing, alignment modes, reporting address extraction
- **DKIM Analysis** (RFC 6376) — selector probing, key strength assessment, provider-aware credit
- **MTA-STS Analysis** (RFC 8461) — policy file validation, mode parsing
- **TLS-RPT Analysis** (RFC 8460) — reporting address extraction
- **BIMI Analysis** (RFC 9495) — logo and VMC validation
- **DANE/TLSA Analysis** (RFC 7671) — per-MX-host TLSA evaluation, DNSSEC requirement verification
- **DNSSEC Analysis** (RFC 4035) — chain of trust verification
- **CAA Analysis** (RFC 8659) — authorized CA parsing, MPIC awareness
- **NS Delegation Analysis** (RFC 1034) — delegation consistency, lame delegation detection
- **SMTP Transport Analysis** (RFC 3207) — live TLS probing with DNS-inferred fallback (conditional — cloud platforms may block outbound port 25; gracefully skipped when unavailable)

## Infrastructure Analysis

- DNS record lookups (A, AAAA, MX, TXT, NS, CNAME, CAA, SOA, SRV)
- Multi-resolver consensus (Cloudflare, Google, Quad9, OpenDNS, DNS4EU)
- Authoritative vs. resolver propagation comparison
- Registrar/RDAP lookup with caching
- Multi-layer subdomain discovery with intelligent caching (proprietary pipeline)
- DNS infrastructure provider detection and tier classification
- Hosting provider detection (web, DNS, email)
- DNS history timeline via SecurityTrails API (user-provided API key only; 50 req/month hard limit; never called automatically)

## Assessment and Scoring

- CVSS-aligned security posture assessment
- Mail posture classification
- RFC-aligned remediation engine with priority fixes

## Detection and Intelligence

- Email security management provider detection
- AI Surface Scanner (llms.txt, AI crawler governance, prompt injection detection)
- Public exposure checks: secret/credential scanning in publicly accessible page source and JavaScript
- Expanded exposure checks (opt-in): well-known misconfiguration path probing (/.env, /.git, /server-status, etc.) with content validation
- Dangling DNS and subdomain takeover detection
- DMARC external reporting authorization verification
- OpenPhish community phishing URL feed integration (Email Header Analyzer body scanning)

## Platform Features

- Domain analysis with re-analyze capability
- Analysis history with search
- Side-by-side domain comparison
- Statistics dashboard
- JSON export
- Email Header Analyzer — multi-format support (paste, .eml, JSON, .mbox, .txt) with SPF/DKIM/DMARC verification, delivery route tracing, spoofing detection, subject line scam analysis (phone number obfuscation, fake payment amounts, homoglyph brand impersonation), third-party spam vendor detection (Proofpoint, Barracuda, Microsoft SCL, Mimecast), brand mismatch detection, BCC delivery detection, and educational "Understanding This Attack" explainer
- IP Intelligence (reverse lookups, ASN attribution, geolocation)
- Dual intelligence products: Engineer's DNS Intelligence Report (comprehensive technical detail) and Executive's DNS Intelligence Brief (concise board-ready summary with security scorecard)
- Configurable TLP classification (default: TLP:AMBER, with TLP:RED, TLP:AMBER+STRICT, TLP:GREEN and TLP:CLEAR options) aligned with CISA Cyber Hygiene practice and FIRST TLP v2.0
- Report integrity hash (SHA-256 fingerprint binding domain, analysis ID, timestamp, tool version, and results data) with copy-to-clipboard and header preview
- Posture drift detection foundation (canonical SHA-256 hashing for longitudinal monitoring)
- Changelog page
- Security policy page
- Sources and methodology reference

## Security and Infrastructure

- CSRF protection (HMAC-signed tokens)
- Rate limiting (per-IP)
- SSRF hardening
- Multi-resolver DNS client with DoH fallback and UDP fast-probe
- Provider health telemetry
- Concurrent analysis orchestrator with master deadline

## Design Philosophy

- **OSINT methodology**: all data sourced from publicly available, open-source intelligence — DNS queries, CT logs, RDAP, publicly accessible web resources
- **Fresh data**: DNS records always fetched live (TTL=0, no cache)
- **Observation-based language**: no definitive claims, only observations
- **Open-Standard Protocols**: All analysis uses publicly verifiable DNS, SMTP, and HTTP protocols — results can be independently reproduced with standard tools (dig, openssl, curl)
- **RFC-backed**: all analysis grounded in published standards
- **Symbiotic security**: enterprise providers recognized for multi-layer security beyond DNSSEC alone

---

## Automated Verification

Feature parity is enforced by automated Go tests that verify every
schema key is present in orchestrator output. Golden rule tests guard
critical behaviors and prevent regressions.
