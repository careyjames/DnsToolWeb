package analyzer

import (
        "context"
        "fmt"
        "net"
        "strings"

        "github.com/miekg/dns"
)

func (a *Analyzer) AnalyzeHTTPSSVCB(ctx context.Context, domain string) map[string]any {
        result := map[string]any{
                "status":          "success",
                "has_https":       false,
                "has_svcb":        false,
                "https_records":   []map[string]any{},
                "svcb_records":    []map[string]any{},
                "supports_http3":  false,
                "supports_ech":    false,
                "issues":          []string{},
        }

        httpsRecords := a.queryHTTPSRecords(ctx, domain)
        svcbRecords := a.querySVCBRecords(ctx, domain)

        if len(httpsRecords) > 0 {
                result["has_https"] = true
                parsed := parseHTTPSRecords(httpsRecords)
                result["https_records"] = parsed
                updateSVCBCapabilities(result, parsed)
        }

        if len(svcbRecords) > 0 {
                result["has_svcb"] = true
                parsed := parseSVCBRecords(svcbRecords)
                result["svcb_records"] = parsed
        }

        if !result["has_https"].(bool) && !result["has_svcb"].(bool) {
                result["status"] = "info"
                result["message"] = "No HTTPS or SVCB records found"
        } else {
                result["message"] = buildHTTPSMessage(result)
        }

        return result
}

func (a *Analyzer) queryHTTPSRecords(ctx context.Context, domain string) []*dns.HTTPS {
        msg := new(dns.Msg)
        msg.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
        msg.RecursionDesired = true

        resp, err := a.DNS.ExchangeContext(ctx, msg)
        if err != nil || resp == nil {
                return nil
        }

        var records []*dns.HTTPS
        for _, rr := range resp.Answer {
                if h, ok := rr.(*dns.HTTPS); ok {
                        records = append(records, h)
                }
        }
        return records
}

func (a *Analyzer) querySVCBRecords(ctx context.Context, domain string) []*dns.SVCB {
        msg := new(dns.Msg)
        msg.SetQuestion(dns.Fqdn(domain), dns.TypeSVCB)
        msg.RecursionDesired = true

        resp, err := a.DNS.ExchangeContext(ctx, msg)
        if err != nil || resp == nil {
                return nil
        }

        var records []*dns.SVCB
        for _, rr := range resp.Answer {
                if s, ok := rr.(*dns.SVCB); ok {
                        records = append(records, s)
                }
        }
        return records
}

func parseHTTPSRecords(records []*dns.HTTPS) []map[string]any {
        var parsed []map[string]any
        for _, r := range records {
                entry := map[string]any{
                        "priority": r.Priority,
                        "target":   r.Target,
                        "raw":      r.String(),
                }
                parseSvcParams(entry, r.Value)
                parsed = append(parsed, entry)
        }
        return parsed
}

func parseSVCBRecords(records []*dns.SVCB) []map[string]any {
        var parsed []map[string]any
        for _, r := range records {
                entry := map[string]any{
                        "priority": r.Priority,
                        "target":   r.Target,
                        "raw":      r.String(),
                }
                parseSvcParams(entry, r.Value)
                parsed = append(parsed, entry)
        }
        return parsed
}

func parseSvcParams(entry map[string]any, values []dns.SVCBKeyValue) {
        var alpnList []string
        for _, kv := range values {
                alpnList = applySvcParam(entry, kv, alpnList)
        }
        if hasHTTP3(alpnList) {
                entry["http3"] = true
        }
}

func applySvcParam(entry map[string]any, kv dns.SVCBKeyValue, alpnList []string) []string {
        switch v := kv.(type) {
        case *dns.SVCBAlpn:
                entry["alpn"] = v.Alpn
                return v.Alpn
        case *dns.SVCBPort:
                entry["port"] = v.Port
        case *dns.SVCBIPv4Hint:
                entry["ipv4hint"] = ipHintsToStrings(v.Hint)
        case *dns.SVCBIPv6Hint:
                entry["ipv6hint"] = ipHintsToStrings(v.Hint)
        case *dns.SVCBECHConfig:
                entry["ech"] = true
                entry["ech_config_len"] = len(v.ECH)
        case *dns.SVCBMandatory:
                keys := make([]string, len(v.Code))
                for i, c := range v.Code {
                        keys[i] = c.String()
                }
                entry["mandatory"] = keys
        case *dns.SVCBNoDefaultAlpn:
                entry["no_default_alpn"] = true
        }
        return alpnList
}

func ipHintsToStrings(hints []net.IP) []string {
        result := make([]string, len(hints))
        for i, ip := range hints {
                result[i] = ip.String()
        }
        return result
}

func hasHTTP3(alpnList []string) bool {
        for _, proto := range alpnList {
                if proto == "h3" || strings.HasPrefix(proto, "h3-") {
                        return true
                }
        }
        return false
}

func updateSVCBCapabilities(result map[string]any, parsed []map[string]any) {
        for _, rec := range parsed {
                if h3, ok := rec["http3"].(bool); ok && h3 {
                        result["supports_http3"] = true
                }
                if ech, ok := rec["ech"].(bool); ok && ech {
                        result["supports_ech"] = true
                }
        }
}

func buildHTTPSMessage(result map[string]any) string {
        parts := []string{}
        if result["has_https"].(bool) {
                parts = append(parts, "HTTPS records found")
        }
        if result["supports_http3"].(bool) {
                parts = append(parts, "HTTP/3 supported")
        }
        if result["supports_ech"].(bool) {
                parts = append(parts, "ECH (Encrypted Client Hello) enabled")
        }
        if len(parts) == 0 {
                return "SVCB records found"
        }
        return fmt.Sprintf("%s", strings.Join(parts, ", "))
}
