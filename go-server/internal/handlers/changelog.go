// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
//
// CHANGELOG DATE POLICY
// =====================
// Each entry's Date field must reflect the ACTUAL date the feature shipped or
// the incident occurred — NOT the version number prefix, NOT "today", and NOT
// the date the changelog entry was written. Version numbers (26.14.x, 26.13.x)
// are feature-level counters and do NOT encode dates.
//
// When adding a new entry:
//   1. Determine the real ship/event date.
//   2. Use (or create) a named date constant below.
//   3. Reference the constant — never inline a date string.
//
// Canonical date mapping (verified Feb 15, 2026):
//   dateFeb15 — Dual Intelligence Products (Engineer's DNS Intelligence Report & Executive's DNS Intelligence Brief), OpenPhish Threat
//               Intelligence Attribution, Email Header Analyzer Homepage Promotion
//   dateFeb14 — High-Speed Subdomain Discovery
//   dateFeb13 — DNS History Cache, Verify It Yourself, Confidence Indicators,
//               SMTP Transport Verification, AI Surface Scanner, DNS History
//               Timeline, Enhanced Remediation Engine, Email Security Mgmt
//   dateFeb12 — Intelligence Sources Inventory, PTR-Based Hosting Detection,
//               IP-to-ASN Attribution, DANE/TLSA, Go Rewrite, IP Investigation,
//               Email Header Analyzer, Enterprise DNS Detection
//   dateFeb11 — Incident Disclosure, Honest Data Reporting
package handlers

const (
        dateFeb15 = "Feb 15, 2026"
        dateFeb14 = "Feb 14, 2026"
        dateFeb13 = "Feb 13, 2026"
        dateFeb12 = "Feb 12, 2026"
        dateFeb11 = "Feb 11, 2026"
        dateJan22 = "Jan 22, 2026"
        dateNov05 = "Nov 5, 2025"
        dateJun05 = "Jun 5, 2025"
        dateMay24 = "May 24, 2025"
        dateMay18 = "May 18, 2025"
        dateNov23 = "Nov 5, 2023"
        date2019  = "2019"
)

type ChangelogEntry struct {
        Version     string
        Date        string
        Category    string
        Title       string
        Description string
        Icon        string
        IsIncident  bool
        IsLegacy    bool
}

func GetRecentChangelog(n int) []ChangelogEntry {
        all := GetChangelog()
        if len(all) <= n {
                return all
        }
        return all[:n]
}

func GetChangelog() []ChangelogEntry {
        return []ChangelogEntry{
                {
                        Version:     "26.16.11",
                        Date:        dateFeb15,
                        Category:    "Brand",
                        Title:       "Intelligence Document Naming Convention",
                        Description: "Adopted IC (Intelligence Community) document naming: Engineer's DNS Intelligence Report (comprehensive, like a National Intelligence Estimate) and Executive's DNS Intelligence Brief (concise, like a Presidential Daily Brief). Possessive form signals personal ownership. 'DNS Intelligence' avoids MI5 brand conflict. Updated all title tags, print headers, screen headers, OG/Twitter meta, and JSON-LD schema. Homepage hero subtitle now explicitly references both intelligence products.",
                        Icon:        "fas fa-file-alt",
                },
                {
                        Version:     "26.16.10",
                        Date:        dateFeb15,
                        Category:    "Brand",
                        Title:       "Sophistication Accent Tokens & Color Flow",
                        Description: "Added steel-blue (#7d8ea8) and deep navy (#1e3a5f) brand accent tokens for premium intelligence aesthetic. Color flow continuity from homepage through results pages via gradients, borders, and card hover effects. Hero typography upgraded to 3.5rem/800 weight with tighter tracking. All non-status visual elements use brand accents while RFC/CVSS status colors remain untouched.",
                        Icon:        "fas fa-palette",
                },
                {
                        Version:     "26.15.30",
                        Date:        dateFeb15,
                        Category:    "Reporting",
                        Title:       "TLP:AMBER Default & Colored Selector",
                        Description: "Report distribution now defaults to TLP:AMBER per CISA/FIRST standards for security posture reports. TLP selector button and dropdown badges show FIRST TLP v2.0 colors (amber, green, clear). Font cache-busting ensures all icons render correctly across browsers.",
                        Icon:        "fas fa-shield-alt",
                },
                {
                        Version:     "26.15.26",
                        Date:        dateFeb15,
                        Category:    "Reporting",
                        Title:       "Dual Intelligence Products: Engineer's DNS Intelligence Report & Executive's DNS Intelligence Brief",
                        Description: "Two intelligence products: Engineer's DNS Intelligence Report (comprehensive technical detail with all protocol analysis) and Executive's DNS Intelligence Brief (concise board-ready summary with security scorecard, risk posture, and priority actions). Both use the same live analysis data — different formats for different audiences. Includes posture drift detection foundation with canonical SHA-256 hashing for future longitudinal monitoring.",
                        Icon:        "fas fa-file-alt",
                },
                {
                        Version:     "26.15.25",
                        Date:        dateFeb15,
                        Category:    "Transparency",
                        Title:       "OpenPhish Threat Intelligence Attribution",
                        Description: "Added OpenPhish Community Feed to the Intelligence Sources page with its own Threat Intelligence category. Added OpenPhish attribution to the Email Header Analyzer trust bar and body analysis results. Proper credit for the free community phishing URL feed that powers our phishing detection.",
                        Icon:        "fas fa-fish",
                },
                {
                        Version:     "26.15.24",
                        Date:        dateFeb15,
                        Category:    "UX",
                        Title:       "Email Header Analyzer Homepage Promotion",
                        Description: "Added a promotional banner for the Email Header Analyzer on the homepage, matching the IP Investigate card style. Makes the feature more discoverable for users landing on the main page.",
                        Icon:        "fas fa-envelope",
                },
                {
                        Version:     "26.14.7",
                        Date:        dateFeb14,
                        Category:    "Performance",
                        Title:       "High-Speed Subdomain Discovery",
                        Description: "Subdomain probing now uses lightweight UDP DNS queries instead of DNS-over-HTTPS, with independent timeouts and 20-goroutine concurrency. Discovery completes in ~1 second instead of timing out. All subdomains found reliably.",
                        Icon:        "fas fa-tachometer-alt",
                },
                {
                        Version:     "26.14.6",
                        Date:        dateFeb12,
                        Category:    "Transparency",
                        Title:       "Intelligence Sources Inventory",
                        Description: "New /sources page documents every intelligence source used by DNS Tool — DNS resolvers, reverse DNS, Team Cymru ASN attribution, SMTP probing, SecurityTrails, crt.sh, IANA RDAP — with methodology, rate limits, and verification commands. No black boxes.",
                        Icon:        "fas fa-satellite-dish",
                },
                {
                        Version:     "26.14.5",
                        Date:        dateFeb12,
                        Category:    "Intelligence",
                        Title:       "PTR-Based Hosting Detection",
                        Description: "Reverse DNS (PTR) lookups now identify hosting providers directly from IP addresses — the classic Unix-era technique. CloudFront, AWS, Google Cloud, Azure, and more detected without any third-party API.",
                        Icon:        "fas fa-undo-alt",
                },
                {
                        Version:     "26.14.4",
                        Date:        dateFeb12,
                        Category:    "Intelligence",
                        Title:       "IP-to-ASN Attribution",
                        Description: "Team Cymru DNS-based IP-to-ASN mapping identifies which organization owns each IP address (AWS, Cloudflare, Google, etc.). Free community service with no API key and no rate limits.",
                        Icon:        "fas fa-map-marked-alt",
                },
                {
                        Version:     "26.14.3",
                        Date:        dateFeb11,
                        Category:    "Transparency",
                        Title:       "Incident Disclosure: Inaccurate Analysis Output",
                        Description: "A data-processing issue caused some reports to display incorrect analysis results. The root cause has been identified and fixed, and safeguards have been added so incomplete or failed data retrieval can never be silently presented as valid results. We believe in full transparency — you deserve to know when we get it wrong.",
                        Icon:        "fas fa-exclamation-triangle",
                        IsIncident:  true,
                },
                {
                        Version:     "26.14.2",
                        Date:        dateFeb11,
                        Category:    "Transparency",
                        Title:       "Honest Data Reporting",
                        Description: "When third-party data sources are rate-limited or unavailable, reports now say exactly that — never claiming 'no changes detected' when the data simply couldn't be checked. Four clear states: success, rate-limited, error, and partial.",
                        Icon:        "fas fa-gavel",
                },
                {
                        Version:     "26.14.1",
                        Date:        dateFeb13,
                        Category:    "Performance",
                        Title:       "DNS History Cache",
                        Description: "Successful DNS history lookups are now cached for 24 hours, completely isolated from live analysis. Reduces API calls while ensuring live DNS queries are never served stale data.",
                        Icon:        "fas fa-database",
                },
                {
                        Version:     "26.13.7",
                        Date:        dateFeb13,
                        Category:    "Intelligence",
                        Title:       "Verify It Yourself",
                        Description: "Each report now includes terminal commands (dig, openssl, curl) to independently verify the underlying DNS queries. Our analysis adds consensus and RFC evaluation on top — but the raw data is always verifiable.",
                        Icon:        "fas fa-laptop-code",
                },
                {
                        Version:     "26.13.6",
                        Date:        dateFeb13,
                        Category:    "Transparency",
                        Title:       "Confidence Indicators",
                        Description: "Every attribution now shows whether data was directly observed (RDAP lookup, DNS record), inferred (pattern matching), or sourced from a third party — so you know exactly how each conclusion was reached.",
                        Icon:        "fas fa-eye",
                },
                {
                        Version:     "26.13.5",
                        Date:        dateFeb13,
                        Category:    "Security",
                        Title:       "SMTP Transport Verification",
                        Description: "Live STARTTLS probing of mail servers with certificate validation, cipher suite analysis, and TLS version checking. DNS-inferred fallback when direct connection is unavailable.",
                        Icon:        "fas fa-lock",
                },
                {
                        Version:     "26.13.4",
                        Date:        dateFeb13,
                        Category:    "Intelligence",
                        Title:       "AI Surface Scanner",
                        Description: "Detects AI governance signals across domains — llms.txt discovery, AI crawler policies in robots.txt, and prompt injection artifacts. Helps organizations understand their AI exposure.",
                        Icon:        "fas fa-robot",
                },
                {
                        Version:     "26.13.3",
                        Date:        dateFeb13,
                        Category:    "Intelligence",
                        Title:       "DNS History Timeline",
                        Description: "SecurityTrails-powered historical DNS record tracking shows how a domain's DNS configuration has changed over time. Users provide their own API key — never stored server-side.",
                        Icon:        "fas fa-clock",
                },
                {
                        Version:     "26.13.2",
                        Date:        dateFeb13,
                        Category:    "Analysis",
                        Title:       "Enhanced Remediation Engine",
                        Description: "RFC-cited remediation guidance now distinguishes SPF softfail vs hardfail context per RFC 7489 §10.1, with nuanced recommendations based on whether DKIM is present.",
                        Icon:        "fas fa-cogs",
                },
                {
                        Version:     "26.13.1",
                        Date:        dateFeb13,
                        Category:    "Intelligence",
                        Title:       "Email Security Management Detection",
                        Description: "Automatic identification of DMARC monitoring providers, SPF flattening services, and TLS-RPT reporting platforms from DNS records.",
                        Icon:        "fas fa-envelope",
                },
                {
                        Version:     "26.12.2",
                        Date:        dateFeb12,
                        Category:    "Analysis",
                        Title:       "DANE/TLSA Deep Analysis",
                        Description: "Full TLSA record parsing for every MX host with certificate usage, selector, matching type validation, and DNSSEC dependency checking per RFC 7672.",
                        Icon:        "fas fa-shield-alt",
                },
                {
                        Version:     "26.12.1",
                        Date:        dateFeb12,
                        Category:    "Core",
                        Title:       "Go Performance Rewrite",
                        Description: "Complete rewrite from Python/Flask to Go/Gin for dramatically improved performance and concurrency. Multi-resolver consensus DNS client with DoH fallback. The second attempt at Go — this time it stuck.",
                        Icon:        "fas fa-bolt",
                },
                {
                        Version:     "26.12.0",
                        Date:        dateFeb12,
                        Category:    "Intelligence",
                        Title:       "IP Investigation Workflow",
                        Description: "New /investigate page for IP-to-domain reverse lookups with ASN attribution, hosting provider detection, and infrastructure mapping.",
                        Icon:        "fas fa-search-location",
                },
                {
                        Version:     "26.12.E",
                        Date:        dateFeb12,
                        Category:    "Intelligence",
                        Title:       "Email Header Analyzer",
                        Description: "Paste or upload .eml files for SPF/DKIM/DMARC verification, delivery route tracing, spoofing detection, and phishing pattern scanning with critical thinking prompts.",
                        Icon:        "fas fa-envelope-open-text",
                },
                {
                        Version:     "26.12.D",
                        Date:        dateFeb12,
                        Category:    "Security",
                        Title:       "Enterprise DNS Detection & Golden Rules",
                        Description: "Automatic identification of enterprise-grade DNS providers with test-guarded detection. Legacy provider blocklist prevents false enterprise tagging. Protected by automated golden rules tests.",
                        Icon:        "fas fa-building",
                },
        }
}

func GetLegacyChangelog() []ChangelogEntry {
        return []ChangelogEntry{
                {
                        Version:  "26.1.0",
                        Date:     dateJan22,
                        Category: "Core",
                        Title:    "Python Web App: Registrar & Hosting Intelligence",
                        Description: "Major development sprint added RDAP-based registrar detection, hosting provider identification, parallel DNS lookups, and authoritative nameserver queries. The Python/Flask web app grew from basic DNS lookups into a real analysis platform.",
                        Icon:     "fas fa-code",
                        IsLegacy: true,
                },
                {
                        Version:  "25.11.1",
                        Date:     dateNov05,
                        Category: "Core",
                        Title:    "Web App Revival: DoH & Grid Layout",
                        Description: "Returned to the web app after five months. Reset the database, switched to Google's DNS-over-HTTPS for reliability, and reorganized the results into a clean grid layout. The foundation for everything that followed.",
                        Icon:     "fas fa-th",
                        IsLegacy: true,
                },
                {
                        Version:  "25.6.1",
                        Date:     dateJun05,
                        Category: "Core",
                        Title:    "First Web App: Python/Flask on Replit",
                        Description: "DNS Tool became a web application. Built with Python and Flask on Replit — DNS-over-HTTPS queries, PostgreSQL database for scan history, statistics page, and the first version of the analysis results UI. The beginning of dnstool.it-help.tech.",
                        Icon:     "fas fa-globe",
                        IsLegacy: true,
                },
                {
                        Version:  "25.5.2",
                        Date:     dateMay24,
                        Category: "Core",
                        Title:    "CLI Tool: Build System & Quality",
                        Description: "Added reproducible Makefile builds, SonarCloud code quality integration, and archived the working CLI version. The tool was maturing, but the vision was shifting toward a web platform.",
                        Icon:     "fas fa-hammer",
                        IsLegacy: true,
                },
                {
                        Version:  "25.5.1",
                        Date:     dateMay18,
                        Category: "Origins",
                        Title:    "New Name, New Repo: DNS Tool",
                        Description: "DNS Scout was renamed to DNS Tool and given a fresh GitHub repository. Python CLI with terminal output, visual indicators, interactive and batch modes, pre-compiled binaries for Linux, macOS, and Windows. Documentation, FAQ, and changelog from day one.",
                        Icon:     "fas fa-terminal",
                        IsLegacy: true,
                },
                {
                        Version:  "23.11.1",
                        Date:     dateNov23,
                        Category: "Origins",
                        Title:    "DNS Scout: Snap & Launchpad Release",
                        Description: "DNS Scout v6.20 published to Launchpad PPA and Snapcraft — the first packaged, installable release. A working DNS security analysis tool available as a .deb and a Snap. The earliest externally verifiable timestamp of the project.",
                        Icon:     "fas fa-box",
                        IsLegacy: true,
                },
                {
                        Version:  "19.0.0",
                        Date:     date2019,
                        Category: "Origins",
                        Title:    "DNS Scout Is Born",
                        Description: "The project that became DNS Tool started life as DNS Scout — a command-line DNS and email security analysis tool. The seed of an idea: transparent, RFC-compliant domain intelligence with no black boxes.",
                        Icon:     "fas fa-birthday-cake",
                        IsLegacy: true,
                },
        }
}
