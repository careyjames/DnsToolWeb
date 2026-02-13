# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records such as SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, and CAA, with automatic subdomain discovery. The tool aims to provide accurate, RFC-cited, and verifiable results, focusing on elevating domain security through actionable insights and serving as an educational authority. It includes features like an AI Surface Scanner for detecting AI-related governance issues and an IP Investigation workflow.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### Core System
The application is implemented in Go using the Gin framework, providing high performance and concurrency. The architecture follows an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe query generation, and `miekg/dns` for DNS queries.
- **Key Features**: Multi-resolver DNS client with DoH fallback, CT subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, SMTP transport verification, CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling (Observed/Inferred/Third-party), "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB record intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation detection, SMIMEA/OPENPGPKEY email encryption detection, **security.txt** detection, **AI Surface Scanner** (detects llms.txt, AI crawler governance, prefilled AI prompts, CSS-hidden prompt injection artifacts), **SPF redirect= chain handling** with loop detection, and **IP Investigation** for IP-to-domain relationships.
- **SEO**: Comprehensive meta descriptions, Open Graph, and Twitter Card tags.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" ensuring results align with RFCs and industry best practices, enforced by automated golden rules tests.
- **Remediation Logic**: RFC-aligned best practices for SPF (~all vs -all, lookup count), DMARC reporting, DKIM key strength, DNSSEC broken chain, DANE without DNSSEC, and CAA. Posture summary categories include "Action Required", "Monitoring", "Configured", and "Not Configured".

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare, Sources, IP Investigate.
- **Print/PDF Report**: Executive-grade print stylesheet with TLP:CLEAR classification, domain banner, colored sections, B&W laser-safe palette, and controlled page breaks.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella (for consensus).
- **IANA RDAP**: For registry data lookups.
- **ip-api.com**: For visitor IP-to-country lookups.
- **crt.sh**: For Certificate Transparency logs.
- **SecurityTrails**: For DNS history timeline.
- **Team Cymru**: DNS-based IP-to-ASN attribution.

### Database
- **PostgreSQL**: The primary database for persistent storage.