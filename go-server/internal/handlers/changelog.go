// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package handlers

const (
        dateFeb12 = "Feb 12, 2026"
        dateFeb11 = "Feb 11, 2026"
        dateFeb10 = "Feb 10, 2026"
)

type ChangelogEntry struct {
        Version    string
        Date       string
        Category   string
        Title      string
        Description string
        Icon       string
        IsIncident bool
}

func GetChangelog() []ChangelogEntry {
        return []ChangelogEntry{
                {
                        Version:     "26.12.27",
                        Date:        dateFeb12,
                        Category:    "Transparency",
                        Title:       "Intelligence Sources Inventory",
                        Description: "New /sources page documents every intelligence source used by DNS Tool — DNS resolvers, reverse DNS, Team Cymru ASN attribution, SMTP probing, SecurityTrails, crt.sh, IANA RDAP — with methodology, rate limits, and verification commands. No black boxes.",
                        Icon:        "fas fa-satellite-dish",
                },
                {
                        Version:     "26.12.26",
                        Date:        dateFeb12,
                        Category:    "Intelligence",
                        Title:       "PTR-Based Hosting Detection",
                        Description: "Reverse DNS (PTR) lookups now identify hosting providers directly from IP addresses — the classic Unix-era technique. CloudFront, AWS, Google Cloud, Azure, and more detected without any third-party API.",
                        Icon:        "fas fa-undo-alt",
                },
                {
                        Version:     "26.12.25",
                        Date:        dateFeb12,
                        Category:    "Intelligence",
                        Title:       "IP-to-ASN Attribution",
                        Description: "Team Cymru DNS-based IP-to-ASN mapping identifies which organization owns each IP address (AWS, Cloudflare, Google, etc.). Free community service with no API key and no rate limits.",
                        Icon:        "fas fa-map-marked-alt",
                },
                {
                        Version:     "26.12.24",
                        Date:        dateFeb11,
                        Category:    "Transparency",
                        Title:       "Incident Disclosure: Inaccurate Analysis Output",
                        Description: "On Feb 10–11, a data-processing issue caused some reports to display incorrect analysis results. The root cause has been identified and fixed, and safeguards have been added so incomplete or failed data retrieval can never be silently presented as valid results. We believe in full transparency — you deserve to know when we get it wrong.",
                        Icon:        "fas fa-exclamation-triangle",
                        IsIncident:  true,
                },
                {
                        Version:     "26.12.23",
                        Date:        dateFeb11,
                        Category:    "Transparency",
                        Title:       "Honest Data Reporting",
                        Description: "When third-party data sources are rate-limited or unavailable, reports now say exactly that — never claiming 'no changes detected' when the data simply couldn't be checked. Four clear states: success, rate-limited, error, and partial.",
                        Icon:        "fas fa-gavel",
                },
                {
                        Version:     "26.12.22",
                        Date:        dateFeb11,
                        Category:    "Performance",
                        Title:       "DNS History Cache",
                        Description: "Successful DNS history lookups are now cached for 24 hours, completely isolated from live analysis. Reduces API calls while ensuring live DNS queries are never served stale data.",
                        Icon:        "fas fa-database",
                },
                {
                        Version:     "26.12.21",
                        Date:        dateFeb11,
                        Category:    "Intelligence",
                        Title:       "Verify It Yourself",
                        Description: "Each report now includes terminal commands (dig, openssl, curl) to independently verify the underlying DNS queries. Our analysis adds consensus and RFC evaluation on top — but the raw data is always verifiable.",
                        Icon:        "fas fa-laptop-code",
                },
                {
                        Version:     "26.12.20",
                        Date:        dateFeb11,
                        Category:    "Transparency",
                        Title:       "Confidence Indicators",
                        Description: "Every attribution now shows whether data was directly observed (RDAP lookup, DNS record), inferred (pattern matching), or sourced from a third party — so you know exactly how each conclusion was reached.",
                        Icon:        "fas fa-eye",
                },
                {
                        Version:     "26.12.19",
                        Date:        dateFeb11,
                        Category:    "Security",
                        Title:       "SMTP Transport Verification",
                        Description: "Live STARTTLS probing of mail servers with certificate validation, cipher suite analysis, and TLS version checking. DNS-inferred fallback when direct connection is unavailable.",
                        Icon:        "fas fa-lock",
                },
                {
                        Version:     "26.12.18",
                        Date:        dateFeb10,
                        Category:    "Analysis",
                        Title:       "Enhanced Remediation Engine",
                        Description: "RFC-cited remediation guidance now distinguishes SPF softfail vs hardfail context per RFC 7489 §10.1, with nuanced recommendations based on whether DKIM is present.",
                        Icon:        "fas fa-cogs",
                },
                {
                        Version:     "26.12.17",
                        Date:        dateFeb10,
                        Category:    "Intelligence",
                        Title:       "Email Security Management Detection",
                        Description: "Automatic identification of DMARC monitoring providers (Valimail, dmarcian, Agari, etc.), SPF flattening services, and TLS-RPT reporting platforms from DNS records.",
                        Icon:        "fas fa-envelope",
                },
                {
                        Version:     "26.12.16",
                        Date:        dateFeb10,
                        Category:    "Analysis",
                        Title:       "DANE/TLSA Deep Analysis",
                        Description: "Full TLSA record parsing for every MX host with certificate usage, selector, matching type validation, and DNSSEC dependency checking per RFC 7672.",
                        Icon:        "fas fa-shield-alt",
                },
                {
                        Version:     "26.12.15",
                        Date:        dateFeb10,
                        Category:    "Core",
                        Title:       "Go Performance Rewrite",
                        Description: "Complete rewrite from Python/Flask to Go/Gin for dramatically improved performance and concurrency. Multi-resolver consensus DNS client with DoH fallback across Cloudflare, Google, Quad9, and OpenDNS.",
                        Icon:        "fas fa-bolt",
                },
        }
}
