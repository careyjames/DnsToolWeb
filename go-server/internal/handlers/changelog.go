package handlers

type ChangelogEntry struct {
        Version     string
        Date        string
        Category    string
        Title       string
        Description string
        Icon        string
}

func GetChangelog() []ChangelogEntry {
        return []ChangelogEntry{
                {
                        Version:     "26.12.18",
                        Date:        "Feb 2026",
                        Category:    "Transparency",
                        Title:       "Confidence Indicators",
                        Description: "Every attribution now shows whether data was directly observed (RDAP lookup, DNS record), inferred (pattern matching), or sourced from a third party — so you know exactly how each conclusion was reached.",
                        Icon:        "fas fa-microscope",
                },
                {
                        Version:     "26.12.19",
                        Date:        "Feb 2026",
                        Category:    "Intelligence",
                        Title:       "Verify It Yourself",
                        Description: "Each report now includes terminal commands (dig, openssl, curl) to independently verify the underlying DNS queries. Our analysis adds consensus and RFC evaluation on top — but the raw data is always verifiable.",
                        Icon:        "fas fa-terminal",
                },
                {
                        Version:     "26.12.17",
                        Date:        "Feb 2026",
                        Category:    "Analysis",
                        Title:       "Enhanced Remediation Engine",
                        Description: "RFC-cited remediation guidance now distinguishes SPF softfail vs hardfail context per RFC 7489 §10.1, with nuanced recommendations based on whether DKIM is present.",
                        Icon:        "fas fa-wrench",
                },
                {
                        Version:     "26.12.16",
                        Date:        "Jan 2026",
                        Category:    "Security",
                        Title:       "SMTP Transport Verification",
                        Description: "Live STARTTLS probing of mail servers with certificate validation, cipher suite analysis, and TLS version checking. DNS-inferred fallback when direct connection is unavailable.",
                        Icon:        "fas fa-lock",
                },
                {
                        Version:     "26.12.15",
                        Date:        "Jan 2026",
                        Category:    "Intelligence",
                        Title:       "Email Security Management Detection",
                        Description: "Automatic identification of DMARC monitoring providers (Valimail, dmarcian, Agari, etc.), SPF flattening services, and TLS-RPT reporting platforms from DNS records.",
                        Icon:        "fas fa-user-shield",
                },
                {
                        Version:     "26.12.14",
                        Date:        "Jan 2026",
                        Category:    "Analysis",
                        Title:       "DANE/TLSA Deep Analysis",
                        Description: "Full TLSA record parsing for every MX host with certificate usage, selector, matching type validation, and DNSSEC dependency checking per RFC 7672.",
                        Icon:        "fas fa-shield-alt",
                },
                {
                        Version:     "26.12.13",
                        Date:        "Dec 2025",
                        Category:    "Core",
                        Title:       "Multi-Resolver Consensus",
                        Description: "Every DNS query is sent to Cloudflare, Google, Quad9, and OpenDNS simultaneously. Results are cross-referenced to detect inconsistencies and ensure authoritative data.",
                        Icon:        "fas fa-network-wired",
                },
        }
}
