// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package analyzer

import (
        "context"
        "fmt"
        "regexp"
        "strings"
)

var tlsrptRUARe = regexp.MustCompile(`(?i)rua=([^;\s]+)`)

func (a *Analyzer) AnalyzeTLSRPT(ctx context.Context, domain string) map[string]any {
        tlsrptDomain := fmt.Sprintf("_smtp._tls.%s", domain)
        records := a.DNS.QueryDNS(ctx, "TXT", tlsrptDomain)

        if len(records) == 0 {
                return map[string]any{
                        "status":  "warning",
                        "message": "No TLS-RPT record found",
                        "record":  nil,
                        "rua":     nil,
                }
        }

        var validRecords []string
        for _, r := range records {
                if strings.HasPrefix(strings.ToLower(r), "v=tlsrptv1") {
                        validRecords = append(validRecords, r)
                }
        }

        if len(validRecords) == 0 {
                return map[string]any{
                        "status":  "warning",
                        "message": "No valid TLS-RPT record found",
                        "record":  nil,
                        "rua":     nil,
                }
        }

        record := validRecords[0]
        var rua *string
        if m := tlsrptRUARe.FindStringSubmatch(record); m != nil {
                rua = &m[1]
        }

        return map[string]any{
                "status":  "success",
                "message": "TLS-RPT configured - receiving TLS delivery reports",
                "record":  record,
                "rua":     derefStr(rua),
        }
}
