# DNS Tool — Mission Statement

## Mission

DNS Tool exists to produce actionable domain security intelligence from publicly observable data — transparently, independently verifiably, and without requiring authorization from or interaction with the target.

We operate as a disciplined OSINT intelligence platform: we collect from the widest available set of redundant public sources, cross-reference and corroborate findings across those sources, classify every attribution by confidence level, and present conclusions that any competent analyst can independently reproduce using standard tools.

## Core Principles

### 1. Multi-Source Collection
No single source is sufficient. We gather intelligence from every publicly accessible layer — authoritative DNS, protocol-specific records, resolver consensus, registry data, Certificate Transparency logs, infrastructure patterns, third-party enrichment, and web-layer configuration. Redundancy is not waste; it is how you build confidence.

### 2. Source Authority Hierarchy
Not all sources are equal. Authoritative DNS declarations outweigh resolver observations. Protocol records (SPF, DKIM, DMARC) carry their RFC-defined semantics. Third-party data enriches but never overrides primary sources. Every finding carries its provenance so the consumer knows exactly what weight to assign.

### 3. Passive Collection Only
We read publicly available DNS records, check publicly accessible URLs, and produce intelligence from publicly observable data. We do not attempt to exploit any vulnerability, bypass any access control, or interact with any system in a way that requires authorization. If it is not already public, we do not collect it.

### 4. Independent Verifiability
Every conclusion we present must be reproducible. We provide "Verify It Yourself" terminal commands — `dig`, `openssl`, `curl` — so any analyst can confirm our findings independently. If we cannot show you how to verify a claim, we should not be making it.

### 5. RFC Compliance
Our analysis is grounded in the RFCs that define the protocols we examine. SPF evaluation follows RFC 7208. DMARC alignment follows RFC 7489. Certificate Transparency follows RFC 6962. DANE/TLSA follows RFC 6698. We do not invent interpretations — we implement the standards.

### 6. Confidence Taxonomy
Every attribution is classified: **Observed** (directly witnessed in authoritative data), **Inferred** (derived from patterns in primary data), or **Third-party** (sourced from external enrichment). The consumer always knows the basis for each finding.

### 7. Transparency of Method
We disclose what sources we use, what methods we employ, and what limitations exist. Our intelligence sources inventory shows exactly where every data point originated. We do not hide behind black-box analysis.

### 8. Intelligence, Not Data
Raw DNS records are data. Understanding what those records mean for an organization's security posture — that is intelligence. We classify, cross-reference, assess risk, and produce two intelligence products: the **Engineer's DNS Intelligence Report** (full technical detail) and the **Executive's DNS Intelligence Brief** (condensed, board-ready, with security scorecard). Both carry TLP classification under FIRST TLP v2.0.

### 9. No Paid Dependencies by Default
Core analysis runs on free, public data sources. No API key is required for a complete security audit. Paid enrichment (SecurityTrails, etc.) is available when users provide their own keys — but the baseline product stands on its own.

### 10. Reality Over Marketing
Every claim in our reports must be backed by implemented, tested code. If a feature is planned but not shipped, we say "on the roadmap." We do not present aspirational capabilities as current functionality.

---

*"Go out and gather as many different redundant sources of intelligence as you can, and then classify and analyze."*

**© 2024–2026 IT Help San Diego Inc. — DNS Security Intelligence**
