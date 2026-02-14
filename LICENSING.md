# Licensing Model (Open Core)

`DnsToolWeb` is licensed under **Business Source License 1.1 (BUSL-1.1)** with a Change Date of **2029-02-14**, after which it converts to **Apache-2.0**.

## What this means

### You can:
- Read, study, and learn from the source code
- Modify the code and create derivative works
- Use it for development, testing, research, and education
- Run it in production to audit domains you own or control
- Contribute improvements back to the project

### You cannot:
- Offer it (or a derivative) as a hosted/managed DNS audit service to third parties
- Sell a competing commercial product built on this code

### After 2029-02-14:
The license automatically converts to **Apache-2.0** — fully permissive, no restrictions.

## What is open here

This repository contains the public web application:
- Go/Gin web server, routing, middleware, templates
- DNS client (multi-resolver, DoH fallback)
- SMTP transport probes
- Frontend (Bootstrap dark theme, PWA, print/PDF)
- Analyzer stub interfaces (13 files)
- Golden rules test suite
- Live integration test suite

## What is in the private repo

Advanced intelligence data and implementations live in a separate private repository (`dnstool-intel`), also licensed under **BSL 1.1** with the same terms and Change Date. This includes:
- Provider detection databases
- Scoring algorithms
- Infrastructure classification logic
- AI surface detection patterns
- Remediation intelligence

## How they work together

The public repo runs standalone with reduced functionality. In internal builds, selected stub interfaces are replaced with proprietary implementations at compile time. The two codebases share a Go package boundary and are both licensed under BSL 1.1.

## Contributing

By contributing code to this repository, you agree that your contributions may be used under the terms of the BSL 1.1 (and the Apache-2.0 license after the Change Date). A Contributor License Agreement (CLA) may be required for substantial contributions.

## Questions

For licensing inquiries or commercial arrangements, contact: licensing@it-help.tech
