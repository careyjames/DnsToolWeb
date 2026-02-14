# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It serves as a **verification instrument** — when a sysadmin changes a DNS record and rescans, they must see the new state immediately. Every conclusion is independently verifiable using standard commands. Philosophy: **No proprietary magic.**

It audits critical DNS records such as SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, and CAA, with automatic subdomain discovery and DNS history timeline via SecurityTrails API integration. It includes an AI Surface Scanner for detecting AI-related governance signals and an IP Investigation workflow. All public-facing text uses observation-based language (not definitive claims) per the Analysis Integrity Standard.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application is implemented in Go using the Gin framework, providing high performance and concurrency. The architecture follows an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe query generation, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client (no cross-request cache — TTL=0 for live queries), DoH fallback, CT subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, SMTP transport verification (observation-based language), CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling (Observed/Inferred/Third-party), "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB record intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation detection, SMIMEA/OPENPGPKEY email encryption detection, **security.txt** detection, **AI Surface Scanner** (detects llms.txt, AI crawler governance, prefilled AI prompts, CSS-hidden prompt injection artifacts), **SPF redirect= chain handling** with loop detection, **DNS history timeline** via SecurityTrails API (24h cache, 50 calls/month limit), and **IP Investigation** for IP-to-domain relationships.
- **SEO**: Comprehensive meta descriptions, Open Graph, and Twitter Card tags. All claims observation-based per Analysis Integrity Standard.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" ensuring results align with RFCs and industry best practices, enforced by automated golden rules tests. Observation-based language throughout (e.g., "Transport encryption observed?" not "Is email encrypted?").
- **Remediation Logic**: RFC-aligned best practices for SPF (~all vs -all, lookup count), DMARC reporting, DKIM key strength, DNSSEC broken chain, DANE without DNSSEC, and CAA. Posture summary categories include "Action Required", "Monitoring", "Configured", and "Not Configured".
- **Cache Policy**: DNS client cache disabled (TTL=0) — every scan does live queries. Only defensible caches retained: RDAP (24h, rate-limit protection), DNS History (24h, 50 calls/month), CT subdomains (1h, append-only data), RFC metadata (24h, reference data).

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare, Sources, IP Investigate.
- **Print/PDF Report**: Executive-grade print stylesheet with TLP:CLEAR classification, domain banner, colored sections, B&W laser-safe palette, and controlled page breaks.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella (for consensus).
- **IANA RDAP**: For registry data lookups (24h cache due to aggressive rate limits).
- **ip-api.com**: For visitor IP-to-country lookups.
- **crt.sh**: For Certificate Transparency logs (1h cache, append-only historical data).
- **SecurityTrails**: For DNS history timeline (user-provided API key, no server-side storage; 24h result cache). Users enter their own SecurityTrails API key on the results page — key is sent directly to SecurityTrails and never stored.
- **Team Cymru**: DNS-based IP-to-ASN attribution.

### Database
- **PostgreSQL**: The primary database for persistent storage.
