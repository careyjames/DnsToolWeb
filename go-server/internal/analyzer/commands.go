// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package analyzer

import (
        "fmt"
        "sort"
        "strings"
)

const (
        sectionDNSRecords    = "DNS Records"
        sectionEmailAuth     = "Email Authentication"
        sectionTransport     = "Transport Security"
        sectionDomainSec     = "Domain Security"
        sectionBrandTrust    = "Brand & Trust"
        sectionInfraIntel    = "Infrastructure Intelligence"
        sectionAISurface     = "AI Surface"
        rfcDNS1035           = "RFC 1035"
        rfcSPF7208           = "RFC 7208"
        rfcDMARC7489         = "RFC 7489"
        rfcDKIM6376          = "RFC 6376"
        rfcDNSSEC4035        = "RFC 4035"
        rfcDANE7672          = "RFC 7672"
        rfcTLSA6698          = "RFC 6698"
        rfcMTASTS8461        = "RFC 8461"
        rfcTLSRPT8460        = "RFC 8460"
        rfcBIMIDraft         = "BIMI Draft"
        rfcCAA8659           = "RFC 8659"
        rfcHTTPSSVCB9460     = "RFC 9460"
        rfcSecurityTxt9116   = "RFC 9116"
        rfcCDS7344           = "RFC 7344"
)

type VerifyCommand struct {
        Section     string
        Description string
        Command     string
        RFC         string
}

func GenerateVerificationCommands(domain string, results map[string]any) []VerifyCommand {
        var cmds []VerifyCommand
        cmds = append(cmds, generateDNSRecordCommands(domain)...)
        cmds = append(cmds, generateSPFCommands(domain)...)
        cmds = append(cmds, generateDMARCCommands(domain)...)
        cmds = append(cmds, generateDKIMCommands(domain, results)...)
        cmds = append(cmds, generateDNSSECCommands(domain)...)
        cmds = append(cmds, generateDANECommands(domain, results)...)
        cmds = append(cmds, generateMTASTSCommands(domain)...)
        cmds = append(cmds, generateTLSRPTCommands(domain)...)
        cmds = append(cmds, generateBIMICommands(domain)...)
        cmds = append(cmds, generateCAACommands(domain)...)
        cmds = append(cmds, generateHTTPSSVCBCommands(domain)...)
        cmds = append(cmds, generateCDSCommands(domain)...)
        cmds = append(cmds, generateRegistrarCommands(domain)...)
        cmds = append(cmds, generateSMTPCommands(domain, results)...)
        cmds = append(cmds, generateCTCommands(domain)...)
        cmds = append(cmds, generateDMARCReportAuthCommands(domain, results)...)
        cmds = append(cmds, generateSecurityTxtCommands(domain)...)
        cmds = append(cmds, generateAISurfaceCommands(domain)...)
        cmds = append(cmds, generateASNCommands(results)...)
        return cmds
}

func generateDNSRecordCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionDNSRecords, "Query A records (IPv4)", fmt.Sprintf("dig +noall +answer %s A", domain), rfcDNS1035},
                {sectionDNSRecords, "Query AAAA records (IPv6)", fmt.Sprintf("dig +noall +answer %s AAAA", domain), rfcDNS1035},
                {sectionDNSRecords, "Query MX records (mail servers)", fmt.Sprintf("dig +noall +answer %s MX", domain), rfcDNS1035},
                {sectionDNSRecords, "Query NS records (nameservers)", fmt.Sprintf("dig +noall +answer %s NS", domain), rfcDNS1035},
                {sectionDNSRecords, "Query TXT records", fmt.Sprintf("dig +noall +answer %s TXT", domain), rfcDNS1035},
        }
}

func generateSPFCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionEmailAuth, "Check SPF record", fmt.Sprintf("dig +short %s TXT | grep -i spf", domain), rfcSPF7208},
        }
}

func generateDMARCCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionEmailAuth, "Check DMARC policy", fmt.Sprintf("dig +short _dmarc.%s TXT", domain), rfcDMARC7489},
        }
}

func generateDKIMCommands(domain string, results map[string]any) []VerifyCommand {
        selectors := extractDKIMSelectors(results)
        if len(selectors) == 0 {
                selectors = []string{"default", "google", "selector1", "selector2"}
        }
        var cmds []VerifyCommand
        for _, sel := range selectors {
                cmds = append(cmds, VerifyCommand{
                        sectionEmailAuth,
                        fmt.Sprintf("Check DKIM key for selector '%s'", sel),
                        fmt.Sprintf("dig +short %s._domainkey.%s TXT", sel, domain),
                        rfcDKIM6376,
                })
        }
        return cmds
}

func generateDNSSECCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionDomainSec, "Check DNSSEC DNSKEY records", fmt.Sprintf("dig +dnssec +noall +answer %s DNSKEY", domain), rfcDNSSEC4035},
                {sectionDomainSec, "Check DNSSEC DS records", fmt.Sprintf("dig +noall +answer %s DS", domain), rfcDNSSEC4035},
                {sectionDomainSec, "Validate DNSSEC chain (requires DNSSEC-validating resolver)", fmt.Sprintf("dig +dnssec +cd %s A @1.1.1.1", domain), rfcDNSSEC4035},
        }
}

func generateDANECommands(domain string, results map[string]any) []VerifyCommand {
        mxHosts := extractMXHostsFromResults(results)
        var cmds []VerifyCommand
        if len(mxHosts) > 0 {
                for _, mx := range mxHosts {
                        cmds = append(cmds, VerifyCommand{
                                sectionTransport,
                                fmt.Sprintf("Check TLSA record for %s", mx),
                                fmt.Sprintf("dig +noall +answer _25._tcp.%s TLSA", mx),
                                rfcDANE7672,
                        })
                }
                cmds = append(cmds, VerifyCommand{
                        sectionTransport,
                        fmt.Sprintf("Verify TLS certificate on primary MX (%s)", mxHosts[0]),
                        fmt.Sprintf("openssl s_client -starttls smtp -connect %s:25 -servername %s 2>/dev/null | openssl x509 -noout -subject -dates", mxHosts[0], mxHosts[0]),
                        rfcTLSA6698,
                })
        } else {
                cmds = append(cmds, VerifyCommand{
                        sectionTransport,
                        "Check TLSA record (replace MX_HOST with actual MX)",
                        fmt.Sprintf("dig +noall +answer _25._tcp.MX_HOST TLSA"),
                        rfcDANE7672,
                })
        }
        return cmds
}

func generateMTASTSCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionTransport, "Check MTA-STS DNS record", fmt.Sprintf("dig +short _mta-sts.%s TXT", domain), rfcMTASTS8461},
                {sectionTransport, "Fetch MTA-STS policy file", fmt.Sprintf("curl -sL https://mta-sts.%s/.well-known/mta-sts.txt", domain), rfcMTASTS8461},
        }
}

func generateTLSRPTCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionTransport, "Check TLS-RPT record", fmt.Sprintf("dig +short _smtp._tls.%s TXT", domain), rfcTLSRPT8460},
        }
}

func generateBIMICommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionBrandTrust, "Check BIMI record", fmt.Sprintf("dig +short default._bimi.%s TXT", domain), rfcBIMIDraft},
        }
}

func generateCAACommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionBrandTrust, "Check CAA records (certificate authority authorization)", fmt.Sprintf("dig +noall +answer %s CAA", domain), rfcCAA8659},
        }
}

func generateRegistrarCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionInfraIntel, "RDAP domain registration lookup", fmt.Sprintf("curl -sL 'https://rdap.org/domain/%s' | python3 -m json.tool | head -50", domain), "RFC 9083"},
        }
}

func generateSMTPCommands(domain string, results map[string]any) []VerifyCommand {
        mxHosts := extractMXHostsFromResults(results)
        var cmds []VerifyCommand
        if len(mxHosts) > 0 {
                cmds = append(cmds, VerifyCommand{
                        sectionTransport,
                        fmt.Sprintf("Test STARTTLS on primary MX (%s)", mxHosts[0]),
                        fmt.Sprintf("openssl s_client -starttls smtp -connect %s:25 -servername %s </dev/null 2>/dev/null | head -5", mxHosts[0], mxHosts[0]),
                        "RFC 3207",
                })
        }
        return cmds
}

func generateCTCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionInfraIntel, "Search Certificate Transparency logs", fmt.Sprintf("curl -s 'https://crt.sh/?q=%%25.%s&output=json' | python3 -c \"import json,sys; [print(e['name_value']) for e in json.load(sys.stdin)]\" | sort -u | head -20", domain), "RFC 6962"},
        }
}

func generateDMARCReportAuthCommands(domain string, results map[string]any) []VerifyCommand {
        ruaTargets := extractDMARCRuaTargets(results)
        var cmds []VerifyCommand
        for _, target := range ruaTargets {
                if target != domain {
                        cmds = append(cmds, VerifyCommand{
                                sectionEmailAuth,
                                fmt.Sprintf("Check external DMARC report authorization for %s", target),
                                fmt.Sprintf("dig +short %s._report._dmarc.%s TXT", domain, target),
                                rfcDMARC7489,
                        })
                }
        }
        return cmds
}

func generateHTTPSSVCBCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionDNSRecords, "Check HTTPS/SVCB records", fmt.Sprintf("dig +noall +answer %s HTTPS", domain), rfcHTTPSSVCB9460},
        }
}

func generateASNCommands(results map[string]any) []VerifyCommand {
        ips := extractIPsFromResults(results)
        var cmds []VerifyCommand
        for _, ip := range ips {
                cmds = append(cmds, VerifyCommand{
                        sectionInfraIntel,
                        fmt.Sprintf("ASN lookup for %s (Team Cymru)", ip),
                        fmt.Sprintf("dig +short %s.origin.asn.cymru.com TXT", reverseIP(ip)),
                        "",
                })
        }
        return cmds
}

func generateCDSCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionDomainSec, "Check CDS/CDNSKEY automation records", fmt.Sprintf("dig +noall +answer %s CDS", domain), rfcCDS7344},
        }
}

func generateAISurfaceCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionAISurface, "Check for llms.txt", fmt.Sprintf("curl -sI https://%s/llms.txt | head -5", domain), ""},
                {sectionAISurface, "Check robots.txt for AI crawler rules", fmt.Sprintf("curl -s https://%s/robots.txt | grep -i -E 'GPTBot|ChatGPT|Claude|Anthropic|Google-Extended|CCBot|PerplexityBot'", domain), ""},
        }
}

func generateSecurityTxtCommands(domain string) []VerifyCommand {
        return []VerifyCommand{
                {sectionInfraIntel, "Check security.txt", fmt.Sprintf("curl -sL https://%s/.well-known/security.txt | head -20", domain), rfcSecurityTxt9116},
        }
}

func extractMXHostsFromResults(results map[string]any) []string {
        dns, ok := results["dns"]
        if !ok {
                return nil
        }
        dnsMap, ok := dns.(map[string]any)
        if !ok {
                return nil
        }
        mxRaw, ok := dnsMap["mx"]
        if !ok {
                return nil
        }
        return parseMXHostEntries(mxRaw)
}

func parseMXHostEntries(mxRaw any) []string {
        var hosts []string
        switch v := mxRaw.(type) {
        case []any:
                for _, entry := range v {
                        hosts = appendMXHost(hosts, entry)
                }
        case []map[string]any:
                for _, entry := range v {
                        hosts = appendMXHost(hosts, entry)
                }
        }
        return hosts
}

func appendMXHost(hosts []string, entry any) []string {
        switch e := entry.(type) {
        case map[string]any:
                if host, ok := e["host"].(string); ok {
                        host = strings.TrimSuffix(host, ".")
                        if host != "" {
                                hosts = append(hosts, host)
                        }
                } else if exchange, ok := e["exchange"].(string); ok {
                        exchange = strings.TrimSuffix(exchange, ".")
                        if exchange != "" {
                                hosts = append(hosts, exchange)
                        }
                }
        case string:
                parts := strings.Fields(e)
                if len(parts) >= 2 {
                        host := strings.TrimSuffix(parts[len(parts)-1], ".")
                        if host != "" {
                                hosts = append(hosts, host)
                        }
                }
        }
        return hosts
}

func extractDKIMSelectors(results map[string]any) []string {
        dkim, ok := results["dkim_analysis"]
        if !ok {
                dkim, ok = results["dkim"]
                if !ok {
                        return nil
                }
        }
        dkimMap, ok := dkim.(map[string]any)
        if !ok {
                return nil
        }
        selectors, ok := dkimMap["selectors"]
        if !ok {
                return nil
        }
        var result []string
        switch sel := selectors.(type) {
        case map[string]any:
                for selectorName := range sel {
                        selectorName = strings.TrimSuffix(selectorName, "._domainkey")
                        result = append(result, selectorName)
                }
        case []any:
                for _, s := range sel {
                        switch v := s.(type) {
                        case string:
                                result = append(result, v)
                        case map[string]any:
                                if name, ok := v["selector"].(string); ok {
                                        result = append(result, name)
                                } else if name, ok := v["name"].(string); ok {
                                        result = append(result, name)
                                }
                        }
                }
        }
        if len(result) == 0 {
                return nil
        }
        sort.Strings(result)
        return result
}

func extractDMARCRuaTargets(results map[string]any) []string {
        extAuth, ok := results["dmarc_report_auth"]
        if !ok {
                dmarc, ok := results["dmarc"]
                if !ok {
                        return nil
                }
                dmarcMap, ok := dmarc.(map[string]any)
                if !ok {
                        return nil
                }
                extAuth, ok = dmarcMap["external_report_auth"]
                if !ok {
                        return nil
                }
        }
        extAuthMap, ok := extAuth.(map[string]any)
        if !ok {
                return nil
        }
        targets, ok := extAuthMap["external_domains"]
        if !ok {
                targets, ok = extAuthMap["domains"]
                if !ok {
                        return nil
                }
        }
        targetList, ok := targets.([]any)
        if !ok {
                return nil
        }
        var result []string
        for _, t := range targetList {
                switch v := t.(type) {
                case string:
                        result = append(result, v)
                case map[string]any:
                        if d, ok := v["domain"].(string); ok {
                                result = append(result, d)
                        }
                }
        }
        return result
}

func extractIPsFromResults(results map[string]any) []string {
        dns, ok := results["dns"]
        if !ok {
                return nil
        }
        dnsMap, ok := dns.(map[string]any)
        if !ok {
                return nil
        }
        var ips []string
        if aRecords, ok := dnsMap["a"]; ok {
                if aList, ok := aRecords.([]any); ok {
                        for _, a := range aList {
                                if ip, ok := a.(string); ok && len(ips) < 2 {
                                        ips = append(ips, ip)
                                }
                        }
                }
        }
        return ips
}

func reverseIP(ip string) string {
        parts := strings.Split(ip, ".")
        if len(parts) != 4 {
                return ip
        }
        return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}
