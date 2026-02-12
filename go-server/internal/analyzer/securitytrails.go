package analyzer

import (
        "bytes"
        "context"
        "encoding/json"
        "fmt"
        "log/slog"
        "net/http"
        "os"
        "sync"
        "time"
)

var (
        securityTrailsEnabled bool
        securityTrailsAPIKey  string
        securityTrailsOnce    sync.Once
)

func initSecurityTrails() {
        securityTrailsOnce.Do(func() {
                securityTrailsAPIKey = os.Getenv("SECURITYTRAILS_API_KEY")
                securityTrailsEnabled = securityTrailsAPIKey != ""
                if securityTrailsEnabled {
                        slog.Info("SecurityTrails API enabled")
                }
        })
}

var securityTrailsHTTPClient = &http.Client{
        Timeout: 10 * time.Second,
}

type stSubdomainsResponse struct {
        Subdomains []string `json:"subdomains"`
}

type stSearchResponse struct {
        Records []struct {
                Hostname string `json:"hostname"`
        } `json:"records"`
}

type STFetchStatus struct {
        RateLimited bool
        Errored     bool
}

func FetchSubdomains(ctx context.Context, domain string) ([]string, *STFetchStatus, error) {
        initSecurityTrails()
        if !securityTrailsEnabled {
                return nil, nil, nil
        }

        url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains?children_only=false&include_inactive=false", domain)

        req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
        if err != nil {
                slog.Warn("SecurityTrails: failed to create request", "domain", domain, "error", err)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }
        req.Header.Set("APIKEY", securityTrailsAPIKey)
        req.Header.Set("Accept", "application/json")

        resp, err := securityTrailsHTTPClient.Do(req)
        if err != nil {
                slog.Warn("SecurityTrails: request failed", "domain", domain, "error", err)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusTooManyRequests {
                slog.Warn("SecurityTrails: rate limited (429)", "domain", domain)
                return []string{}, &STFetchStatus{RateLimited: true}, nil
        }

        if resp.StatusCode != http.StatusOK {
                slog.Warn("SecurityTrails: unexpected status", "domain", domain, "status", resp.StatusCode)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }

        var stResp stSubdomainsResponse
        if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
                slog.Warn("SecurityTrails: failed to parse response", "domain", domain, "error", err)
                return []string{}, &STFetchStatus{Errored: true}, nil
        }

        fqdns := make([]string, 0, len(stResp.Subdomains))
        for _, label := range stResp.Subdomains {
                if label == "" {
                        continue
                }
                fqdns = append(fqdns, label+"."+domain)
        }

        slog.Info("SecurityTrails: discovered subdomains", "domain", domain, "count", len(fqdns))
        return fqdns, nil, nil
}

func FetchDomainsByIP(ctx context.Context, ip string) ([]string, error) {
        initSecurityTrails()
        if !securityTrailsEnabled {
                return nil, nil
        }

        payload := map[string]any{
                "filter": map[string]string{
                        "ipv4": ip,
                },
        }
        body, err := json.Marshal(payload)
        if err != nil {
                slog.Warn("SecurityTrails: failed to marshal search payload", "ip", ip, "error", err)
                return []string{}, nil
        }

        req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.securitytrails.com/v1/search/list", bytes.NewReader(body))
        if err != nil {
                slog.Warn("SecurityTrails: failed to create search request", "ip", ip, "error", err)
                return []string{}, nil
        }
        req.Header.Set("APIKEY", securityTrailsAPIKey)
        req.Header.Set("Accept", "application/json")
        req.Header.Set("Content-Type", "application/json")

        resp, err := securityTrailsHTTPClient.Do(req)
        if err != nil {
                slog.Warn("SecurityTrails: search request failed", "ip", ip, "error", err)
                return []string{}, nil
        }
        defer resp.Body.Close()

        if resp.StatusCode == http.StatusTooManyRequests {
                slog.Warn("SecurityTrails: rate limited (429)", "ip", ip)
                return []string{}, nil
        }

        if resp.StatusCode != http.StatusOK {
                slog.Warn("SecurityTrails: search unexpected status", "ip", ip, "status", resp.StatusCode)
                return []string{}, nil
        }

        var stResp stSearchResponse
        if err := json.NewDecoder(resp.Body).Decode(&stResp); err != nil {
                slog.Warn("SecurityTrails: failed to parse search response", "ip", ip, "error", err)
                return []string{}, nil
        }

        domains := make([]string, 0, len(stResp.Records))
        for _, rec := range stResp.Records {
                if rec.Hostname != "" {
                        domains = append(domains, rec.Hostname)
                }
        }

        slog.Info("SecurityTrails: discovered domains by IP", "ip", ip, "count", len(domains))
        return domains, nil
}
