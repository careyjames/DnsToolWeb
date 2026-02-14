# DNS Tool — Domain Security Audit

## Overview
The DNS Tool is a web-based intelligence platform designed for comprehensive, RFC-compliant domain security analysis. It audits critical DNS records (SPF, DKIM, DMARC, DANE/TLSA, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA), includes automatic subdomain discovery, a DNS history timeline, an AI Surface Scanner, an IP Investigation workflow, and an Email Header Analyzer. The tool prioritizes immediate verification of DNS changes and ensures all conclusions are independently verifiable using standard commands, adhering to a "No proprietary magic" philosophy. It aims to be a verification instrument for sysadmins and a reporting tool for executives, focusing on observation-based language per the Analysis Integrity Standard.

## User Preferences
- Preferred communication style: Simple, everyday language.
- Philosophy: "As open-source as humanly possible while protecting ability to sell as a commercial product."
- Prioritize honest, observation-based reporting aligned with NIST/CISA standards.
- Tool targets both technical sysadmins and non-technical executives (board-level).
- Memory persistence is critical — `replit.md` is the single source of truth between sessions. Update it every session with decisions, changes, and rationale.

## System Architecture

### Core System
The application is built in Go using the Gin framework for high performance. It follows an MVC-style separation.

### Backend
- **Technology Stack**: Go with Gin, `pgx` v5 for PostgreSQL, `sqlc` for type-safe queries, and `miekg/dns` for DNS operations.
- **Key Features**: Multi-resolver DNS client (no cross-request cache), DoH fallback, CT subdomain discovery, posture scoring with CVSS-aligned risk levels, concurrent orchestrator, observation-based SMTP transport verification, CSRF middleware, rate limiting, SSRF hardening, telemetry, confidence labeling, "Verify It Yourself" command equivalence, DMARC external reporting authorization, dangling DNS/subdomain takeover detection, HTTPS/SVCB record intelligence, IP-to-ASN attribution, Edge/CDN vs origin detection, SaaS TXT footprint extraction, CDS/CDNSKEY automation detection, SMIMEA/OPENPGPKEY detection, `security.txt` detection, AI Surface Scanner (detects `llms.txt`, AI crawler governance, prefilled prompts, CSS-hidden prompt injection artifacts), SPF `redirect=` chain handling with loop detection, DNS history timeline, IP Investigation, and Email Header Analyzer (SPF/DKIM/DMARC verification, delivery route tracing, spoofing detection, phishing pattern scanning).
- **Enterprise DNS Detection**: Automatic identification of enterprise-grade DNS providers with a legacy provider blocklist.
- **SMTP Transport Status**: Live SMTP TLS validation with "All Servers", "Inferred", or "No Mail" states.
- **Analysis Integrity**: Adherence to an "Analysis Integrity Standard" for RFC compliance and best practices, enforced by automated golden rules tests.
- **Remediation Engine**: Generates RFC-aligned fixes for various DNS records with severity sorting, examples, and grouping.
- **Mail Posture Labels**: "Strongly Protected", "Moderately Protected", "Limited Protection", "Unprotected", "No Mail Observed" (NIST/CISA aligned).
- **Cache Policy**: DNS client cache disabled. Only RDAP, DNS History, CT subdomains, and RFC metadata retain defensible caches.
- **Licensing**: Public and private repositories use BSL 1.1 (Business Source License), converting to Apache-2.0 on 2029-02-14, supporting an open-core model.

### Frontend
- **Technology**: Server-rendered HTML using Go `html/template`, Bootstrap dark theme, custom CSS, and client-side JavaScript.
- **UI/UX**: PWA support, accessibility, and full mobile responsiveness.
- **Pages**: Index, Results, History, Statistics, Compare, Sources, IP Investigate, Email Header Analyzer.
- **Print/PDF Report**: Executive-grade print stylesheet with TLP:CLEAR classification, domain banner, colored sections, B&W laser-safe palette, and controlled page breaks.

## External Dependencies

### External Services
- **DNS Resolvers**: Cloudflare DNS, Google Public DNS, Quad9, OpenDNS/Cisco Umbrella.
- **IANA RDAP**: Registry data lookups.
- **ip-api.com**: Visitor IP-to-country lookups.
- **crt.sh**: Certificate Transparency logs.
- **SecurityTrails**: DNS history timeline (user-provided API key).
- **Team Cymru**: DNS-based IP-to-ASN attribution.
- **OpenPhish**: Community phishing URL feed.

### Database
- **PostgreSQL**: Primary database for persistent storage. Separate databases for development and production environments.