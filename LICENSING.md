# Licensing Model (Open Core)

`DnsToolWeb` is licensed under **Business Source License 1.1 (BUSL-1.1)** with a rolling Change Date of **three years from the publication of each version**, after which it converts to **Apache-2.0**.

## What this means

### You can:
- Read, study, and learn from the source code
- Modify the code and create derivative works
- Use it for development, testing, research, and education
- Run it in production to audit domains you own or control
- Use it as a security consultant or MSP to audit domains on behalf of your clients
- Run it as an internal tool within your organization for security operations
- Contribute improvements back to the project

### You cannot:
- Offer it (or a derivative) as a hosted, managed, or API-based DNS audit service to third parties
- Embed it in a competing commercial product where DNS security audit functionality is material to the offering
- Sell a competing commercial service built on this code

### What is a "Competitive Offering"?
A product or service that is (a) offered to third parties on a Hosted, Managed, Embedded, or API-based basis AND (b) provides DNS security audit, DNS intelligence, or domain posture assessment functionality that is material to the value of the offering.

**Formal definitions:**

- **Hosted** — Making the functionality of the Licensed Work available to third parties as a service, where the service operator (not the end user) controls the infrastructure.
- **Managed** — Offering the Licensed Work to third parties as a managed service where the operator handles deployment, maintenance, upgrades, or operational responsibility on behalf of the end user.
- **Embedded** — Including the Licensed Work (in whole or in substantial part) in source code, executable code, or packaged form within another product, or packaging a product such that the Licensed Work must be accessed, downloaded, or invoked for it to operate.

### Security consultants and MSPs
Using DNS Tool to audit client domains as part of professional services (consulting, managed security, IT administration) is explicitly permitted. The restriction applies only to offering the tool itself as a standalone hosted or managed product to those clients.

### After the Change Date:
Each version automatically converts to **Apache-2.0** — fully permissive, no restrictions — three years after it is first publicly distributed. For versions published before 2026-02-14, the Change Date is 2029-02-14.

## What is open here

This repository contains the public web application:
- Go/Gin web server, routing, middleware, templates
- DNS client (multi-resolver, DoH fallback, UDP fast-probe)
- SMTP transport probes
- Frontend (Bootstrap dark theme, PWA, dual intelligence products with TLP classification)
- Email Header Analyzer (SPF/DKIM/DMARC verification, spoofing detection, OpenPhish integration)
- IP Intelligence (reverse lookups, ASN attribution, geolocation)
- AI Surface Scanner (llms.txt, AI crawler governance, prompt injection detection)
- DKIM selector discovery and key strength analysis
- Enterprise DNS provider detection
- Edge/CDN vs. origin detection
- SaaS TXT footprint extraction and classification
- Posture drift detection (canonical SHA-256 hashing)
- Remediation engine with RFC-aligned Priority Actions
- Analyzer stub interfaces (10 files — see replit.md for current registry)
- Golden rules test suite
- Live integration test suite

## What is in the private repo

Advanced intelligence data lives in a separate private repository (`dnstool-intel`), also licensed under **BSL 1.1** with the same terms and Change Date. This includes:
- Extended provider detection databases (managed, self-hosted, government classification)
- Confidence level extensions (Corroborated, Stale, Absent)
- Advanced infrastructure classification patterns
- AI surface detection pattern libraries
- Extended IP investigation analysis

## How they work together

The public repo runs standalone with full core functionality. In internal builds, selected stub interfaces are replaced with proprietary implementations at compile time. The two codebases share a Go package boundary and are both licensed under BSL 1.1.

## Contributing

By contributing code to this repository, you agree that your contributions may be used under the terms of the BSL 1.1 (and the Apache-2.0 license after the Change Date). A Contributor License Agreement (CLA) may be required for substantial contributions.

## Commercial Licensing

For organizations that need capabilities beyond the BSL-permitted uses, commercial licenses are available by arrangement. Contact us to discuss your specific requirements.

### What a commercial license can include
- All public repo capabilities plus the complete private intelligence databases
- Self-hosted deployment (on-premises or private cloud)
- Additional deployment and integration options as needed

### Who should contact us
- Security vendors who want to embed DNS audit capabilities in their platform
- Managed service providers who want to offer DNS Tool as a branded service
- Enterprises requiring dedicated deployment with custom integrations
- Organizations needing capabilities beyond the public open-core release

## Questions

For licensing inquiries or commercial arrangements, contact: licensing@it-help.tech
