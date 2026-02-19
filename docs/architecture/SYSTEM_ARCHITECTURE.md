# DNS Tool — System Architecture

## 1. High-Level System Overview

```mermaid
graph TB
    subgraph "Client Layer"
        Browser["Browser<br/>Bootstrap Dark Theme"]
    end

    subgraph "Process Management"
        Gunicorn["Gunicorn (Python)<br/>Process Trampoline"]
        GoBinary["dns-tool-server<br/>Go Binary"]
    end

    subgraph "Application Layer — Go/Gin"
        Router["Gin Router<br/>CSP Middleware"]
        Auth["Google OAuth 2.0 + PKCE<br/>stdlib only"]
        Handlers["Request Handlers<br/>analysis, history, export, dossier"]
        Templates["Go html/template<br/>Nonce-injected CSP"]
    end

    subgraph "Intelligence Engines"
        ICIE["ICIE<br/>Intelligence Classification<br/>& Interpretation Engine"]
        ICAE["ICAE<br/>Intelligence Confidence<br/>Audit Engine"]
    end

    subgraph "Data Collection"
        DNSClient["Multi-Resolver DNS Client<br/>Cloudflare · Google · Quad9 · OpenDNS"]
        SMTP["SMTP Probe<br/>STARTTLS Verification"]
        CT["Certificate Transparency<br/>crt.sh API"]
        HTTP["HTTP Probes<br/>MTA-STS · security.txt · BIMI"]
    end

    subgraph "Storage"
        PG[("PostgreSQL<br/>Neon-backed")]
    end

    subgraph "External (Optional)"
        SecurityTrails["SecurityTrails API<br/>User-key only · 50 req/mo"]
        IntelRepo["dnstool-intel<br/>Private GitHub Repo"]
    end

    Browser -->|"HTTPS"| Gunicorn
    Gunicorn -->|"subprocess"| GoBinary
    GoBinary --> Router
    Router --> Auth
    Router --> Handlers
    Handlers --> Templates
    Handlers --> ICIE
    ICIE --> DNSClient
    ICIE --> SMTP
    ICIE --> CT
    ICIE --> HTTP
    ICIE --> ICAE
    Handlers --> PG
    ICAE --> PG
    Handlers -.->|"user-provided key"| SecurityTrails
    GoBinary -.->|"build tags"| IntelRepo

    classDef engine fill:#1a5276,stroke:#2980b9,color:#fff
    classDef storage fill:#145a32,stroke:#27ae60,color:#fff
    classDef external fill:#7d3c98,stroke:#9b59b6,color:#fff
    class ICIE,ICAE engine
    class PG storage
    class SecurityTrails,IntelRepo external
```

## 2. ICIE — Intelligence Classification & Interpretation Engine

```mermaid
graph LR
    subgraph "Input"
        Domain["Domain Name"]
        Selectors["User DKIM Selectors<br/>(optional)"]
        APIKeys["User API Keys<br/>(optional)"]
    end

    subgraph "Collection Layer"
        DNS["DNS Record Collection<br/>A · AAAA · MX · NS · TXT · SOA<br/>CNAME · CAA · TLSA · SRV"]
        SPF["SPF Analysis<br/>RFC 7208"]
        DMARC["DMARC Analysis<br/>RFC 7489"]
        DKIM["DKIM Discovery<br/>RFC 6376<br/>81+ known selectors"]
        DNSSEC["DNSSEC Validation<br/>RFC 4033-4035"]
        DANE["DANE/TLSA<br/>RFC 6698"]
        MTASTS["MTA-STS<br/>RFC 8461"]
        BIMI["BIMI Check<br/>BIMI Spec"]
        CAA["CAA Records<br/>RFC 8659"]
        SMTP2["SMTP STARTTLS<br/>RFC 3207"]
        CT2["CT Log Search<br/>RFC 6962"]
        SubD["Subdomain Discovery<br/>CT + DNS Enumeration"]
    end

    subgraph "Classification Layer"
        Posture["Mail Posture<br/>Classification"]
        Brand["Brand Security<br/>Verdict Matrix"]
        Transport["Transport Security<br/>Assessment"]
        Remediation["Remediation<br/>Engine"]
    end

    subgraph "Privacy Gate"
        Privacy{"AllSelectorsKnown()?"}
        Public["Public Analysis<br/>No novel intelligence"]
        Private["Private Analysis<br/>Authenticated + novel selectors"]
        Ephemeral["Ephemeral Analysis<br/>Anonymous + novel selectors<br/>Not persisted"]
    end

    subgraph "Output"
        Engineer["Engineer's Report<br/>Technical · RFC-cited"]
        Executive["Executive's Brief<br/>Board-ready · TLP-classified"]
        JSON["JSON Export<br/>Admin-only"]
    end

    Domain --> DNS
    Selectors --> DKIM
    APIKeys -.-> DNS
    DNS --> SPF & DMARC & DKIM & DNSSEC & DANE & MTASTS & BIMI & CAA & SMTP2 & CT2 & SubD
    SPF & DMARC & DKIM --> Posture
    BIMI & CAA & DMARC --> Brand
    DANE & MTASTS & SMTP2 --> Transport
    Posture & Brand & Transport --> Remediation
    Selectors --> Privacy
    Privacy -->|"all known"| Public
    Privacy -->|"novel + auth"| Private
    Privacy -->|"novel + anon"| Ephemeral
    Remediation --> Engineer & Executive & JSON

    classDef rfc fill:#1b4f72,stroke:#2e86c1,color:#fff
    classDef gate fill:#7d6608,stroke:#f1c40f,color:#fff
    classDef output fill:#145a32,stroke:#27ae60,color:#fff
    class SPF,DMARC,DKIM,DNSSEC,DANE,MTASTS,CAA,SMTP2 rfc
    class Privacy,Public,Private,Ephemeral gate
    class Engineer,Executive,JSON output
```

## 3. ICAE — Intelligence Confidence Audit Engine

```mermaid
graph TB
    subgraph "Analysis Output"
        Verdicts["ICIE Verdict Results<br/>email_answer · brand_answer<br/>transport_answer · posture"]
    end

    subgraph "ICAE Evaluation Pipeline"
        Runner["Test Runner<br/>45 Deterministic Cases"]
        
        subgraph "Analysis Layer Cases"
            SPFCases["SPF Protocol<br/>17 cases"]
            DMARCCases["DMARC Protocol<br/>11 cases"]
            DNSSECCases["DNSSEC Protocol<br/>17 cases"]
        end
    end

    subgraph "Maturity Model"
        Dev["Development<br/>Initial implementation"]
        Verified["Verified<br/>Basic validation"]
        Consistent["Consistent<br/>Repeated accuracy"]
        Gold["Gold<br/>Production-grade"]
        Master["Gold Master<br/>Authoritative"]
    end

    subgraph "Storage"
        DB[("ice_audit_runs<br/>ice_case_results<br/>ice_protocol_scores")]
    end

    subgraph "Output"
        Scores["Protocol Confidence Scores<br/>0-100% per protocol"]
        Report["ICAE Audit Report<br/>Pass/Fail per case"]
    end

    Verdicts --> Runner
    Runner --> SPFCases & DMARCCases & DNSSECCases
    SPFCases & DMARCCases & DNSSECCases --> Scores
    Scores --> Dev --> Verified --> Consistent --> Gold --> Master
    Runner --> DB
    Scores --> Report

    classDef maturity fill:#1a5276,stroke:#2980b9,color:#fff
    classDef cases fill:#0e6655,stroke:#1abc9c,color:#fff
    class Dev,Verified,Consistent,Gold,Master maturity
    class SPFCases,DMARCCases,DNSSECCases cases
```

## 4. Two-Repo Open-Core Architecture

```mermaid
graph TB
    subgraph "Public Repo: DnsToolWeb"
        direction TB
        PublicGo["Go Source<br/>All framework code"]
        Stubs["12 OSS Stub Files<br/>//go:build !intel"]
        Templates2["HTML Templates"]
        Static["Static Assets"]
        Tests["Boundary Integrity Tests<br/>12 verification categories"]
        Scripts["Build & Deploy Scripts"]
    end

    subgraph "Private Repo: dnstool-intel"
        direction TB
        Intel["Intelligence Modules<br/>//go:build intel"]
        ProviderDB["Provider Databases<br/>ESP detection · DKIM maps"]
        Methodology["Proprietary Methodology<br/>Classification algorithms"]
        Commercial["Commercial Roadmap<br/>Phase 2-4 plans"]
    end

    subgraph "Build System"
        BuildOSS["OSS Build<br/>go build (default)<br/>Stubs provide safe defaults"]
        BuildIntel["Intel Build<br/>go build -tags intel<br/>Full intelligence capabilities"]
    end

    subgraph "Sync Mechanism"
        Sync["github-intel-sync.mjs<br/>GitHub API read/write"]
    end

    PublicGo --> BuildOSS
    Stubs --> BuildOSS
    PublicGo --> BuildIntel
    Intel --> BuildIntel
    Sync <-->|"push/pull files"| Intel
    Tests -->|"verify no leaks"| PublicGo
    Tests -->|"verify stub contracts"| Stubs

    classDef public fill:#1a5276,stroke:#2980b9,color:#fff
    classDef private fill:#7d3c98,stroke:#9b59b6,color:#fff
    classDef build fill:#145a32,stroke:#27ae60,color:#fff
    class PublicGo,Stubs,Templates2,Static,Tests,Scripts public
    class Intel,ProviderDB,Methodology,Commercial private
    class BuildOSS,BuildIntel build
```

## 5. Email Security Verdict Chain

```mermaid
graph TB
    subgraph "RFC Standards"
        RFC7208["RFC 7208<br/>SPF — Sender IP Authorization"]
        RFC6376["RFC 6376<br/>DKIM — Message Integrity"]
        RFC7489["RFC 7489<br/>DMARC — Policy & Alignment"]
    end

    subgraph "Authentication Triad"
        SPFCheck{"SPF Record?"}
        DKIMCheck{"DKIM Discoverable?"}
        DMARCCheck{"DMARC Policy?"}
    end

    subgraph "DMARC Enforcement Levels"
        Reject["p=reject<br/>Strongest · Messages rejected"]
        Quarantine["p=quarantine<br/>Moderate · Messages flagged"]
        None["p=none<br/>Monitor only · No enforcement"]
        Missing["No DMARC<br/>No policy"]
    end

    subgraph "Supplementary Checks"
        BIMI2["BIMI<br/>Brand Verification"]
        CAA2["CAA (RFC 8659)<br/>Certificate Restriction"]
    end

    subgraph "Brand Security Verdict Matrix"
        Protected["No — Protected<br/>reject + BIMI + CAA"]
        MostlyP["Possible — Mostly Protected<br/>reject + one of BIMI/CAA"]
        PartialP["Possible — Partially Protected<br/>reject + neither BIMI nor CAA"]
        AtRisk["Likely — At Risk<br/>quarantine or none"]
        Exposed["Yes — Exposed<br/>No DMARC"]
    end

    RFC7208 --> SPFCheck
    RFC6376 --> DKIMCheck
    RFC7489 --> DMARCCheck
    DMARCCheck -->|"reject"| Reject
    DMARCCheck -->|"quarantine"| Quarantine
    DMARCCheck -->|"none"| None
    DMARCCheck -->|"missing"| Missing
    Reject --> BIMI2 & CAA2
    BIMI2 & CAA2 -->|"both present"| Protected
    BIMI2 & CAA2 -->|"one present"| MostlyP
    BIMI2 & CAA2 -->|"neither"| PartialP
    Quarantine --> AtRisk
    None --> AtRisk
    Missing --> Exposed

    classDef safe fill:#145a32,stroke:#27ae60,color:#fff
    classDef warn fill:#7d6608,stroke:#f1c40f,color:#fff
    classDef danger fill:#922b21,stroke:#e74c3c,color:#fff
    class Protected safe
    class MostlyP,PartialP warn
    class AtRisk,Exposed danger
```

## 6. Request Lifecycle

```mermaid
sequenceDiagram
    participant B as Browser
    participant G as Gunicorn
    participant R as Gin Router
    participant MW as Middleware
    participant H as Handler
    participant ICIE as ICIE Engine
    participant DNS as DNS Client
    participant DB as PostgreSQL

    B->>G: GET /analyze?domain=example.com
    G->>R: Proxy to Go binary
    R->>MW: CSP · Rate Limit · Session
    MW->>H: analysisHandler()
    
    H->>ICIE: RunFullAnalysis(domain, selectors)
    
    par Concurrent DNS Collection
        ICIE->>DNS: Query Cloudflare 1.1.1.1
        ICIE->>DNS: Query Google 8.8.8.8
        ICIE->>DNS: Query Quad9 9.9.9.9
        ICIE->>DNS: Query OpenDNS 208.67.222.222
    end
    
    DNS-->>ICIE: Merged DNS Results
    
    ICIE->>ICIE: SPF Analysis (RFC 7208)
    ICIE->>ICIE: DMARC Analysis (RFC 7489)
    ICIE->>ICIE: DKIM Discovery (81+ selectors)
    ICIE->>ICIE: DNSSEC Validation
    ICIE->>ICIE: Brand Verdict Matrix
    ICIE->>ICIE: Mail Posture Classification
    
    ICIE-->>H: AnalysisResult{}
    
    H->>H: Privacy Gate (AllSelectorsKnown?)
    
    alt Public Analysis
        H->>DB: Persist full results
    else Private Analysis (auth + novel selectors)
        H->>DB: Persist with privacy flag
    else Ephemeral Analysis (anon + novel selectors)
        H-->>H: Do not persist
    end
    
    H->>R: Render template (engineer/executive)
    R-->>B: HTML Response with CSP nonce
```

## 7. Package Dependency Map

```mermaid
graph TB
    subgraph "cmd"
        Server["cmd/server<br/>main.go — entrypoint"]
    end

    subgraph "internal"
        Config["config<br/>AppVersion · env vars"]
        Middleware["middleware<br/>CSP · rate limit · session"]
        Handlers["handlers<br/>analysis · auth · history<br/>export · dossier · compare"]
        Analyzer["analyzer<br/>ICIE engine core<br/>posture · dkim · spf · dmarc<br/>remediation · brand"]
        AISurface["analyzer/ai_surface<br/>robots.txt · llms.txt<br/>HTTP · poisoning · scanner"]
        ICAE2["icae<br/>ICAE engine<br/>runner · evaluator · report"]
        DNSClient2["dnsclient<br/>Multi-resolver queries"]
        DB2["db<br/>PostgreSQL via pgx"]
        DBQ["dbq<br/>Prepared query cache"]
        Models["models<br/>Data structures"]
        Providers["providers<br/>ESP detection stubs"]
        Telemetry["telemetry<br/>Structured logging"]
        Templates3["templates<br/>Template helpers"]
    end

    Server --> Config & Middleware & Handlers
    Handlers --> Analyzer & ICAE2 & DB2 & Models & Templates3
    Analyzer --> DNSClient2 & Providers & AISurface
    ICAE2 --> DB2 & Models
    Handlers --> Telemetry
    DB2 --> DBQ
    Middleware --> Config & Telemetry

    classDef core fill:#1a5276,stroke:#2980b9,color:#fff
    classDef engine fill:#0e6655,stroke:#1abc9c,color:#fff
    classDef infra fill:#6c3483,stroke:#8e44ad,color:#fff
    class Analyzer,AISurface,ICAE2 engine
    class Server,Handlers,Middleware core
    class DB2,DBQ,DNSClient2,Telemetry infra
```

---

*Generated for DNS Tool v26.20.73 — February 19, 2026*
*Diagrams render natively on GitHub, GitLab, Codeberg, and VS Code with Mermaid plugins.*
