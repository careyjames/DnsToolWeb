package dnsclient

import (
        "context"
        "fmt"
        "io"
        "net"
        "net/http"
        "net/url"
        "time"
)

type SafeHTTPClient struct {
        client    *http.Client
        userAgent string
}

func NewSafeHTTPClient() *SafeHTTPClient {
        return NewSafeHTTPClientWithTimeout(10 * time.Second)
}

func NewSafeHTTPClientWithTimeout(timeout time.Duration) *SafeHTTPClient {
        return &SafeHTTPClient{
                client: &http.Client{
                        Timeout: timeout,
                        Transport: &http.Transport{
                                MaxIdleConns:        20,
                                IdleConnTimeout:     30 * time.Second,
                                DisableKeepAlives:   false,
                                MaxIdleConnsPerHost: 5,
                        },
                        CheckRedirect: func(req *http.Request, via []*http.Request) error {
                                if len(via) >= 5 {
                                        return fmt.Errorf("too many redirects")
                                }
                                if !ValidateURLTarget(req.URL.String()) {
                                        return fmt.Errorf("SSRF protection: redirect target resolves to private IP")
                                }
                                return nil
                        },
                },
                userAgent: UserAgent,
        }
}

func (s *SafeHTTPClient) Get(ctx context.Context, rawURL string) (*http.Response, error) {
        if !ValidateURLTarget(rawURL) {
                return nil, fmt.Errorf("SSRF protection: URL target resolves to private/reserved IP range")
        }

        req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set("User-Agent", s.userAgent)

        return s.client.Do(req)
}

func (s *SafeHTTPClient) GetWithHeaders(ctx context.Context, rawURL string, headers map[string]string) (*http.Response, error) {
        if !ValidateURLTarget(rawURL) {
                return nil, fmt.Errorf("SSRF protection: URL target resolves to private/reserved IP range")
        }

        req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
        if err != nil {
                return nil, err
        }
        req.Header.Set("User-Agent", s.userAgent)
        for k, v := range headers {
                req.Header.Set(k, v)
        }

        return s.client.Do(req)
}

func (s *SafeHTTPClient) ReadBody(resp *http.Response, maxBytes int64) ([]byte, error) {
        defer resp.Body.Close()
        return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func IsPrivateIP(ipStr string) bool {
        ip := net.ParseIP(ipStr)
        if ip == nil {
                return false
        }

        if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
                ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
                return true
        }

        if ip4 := ip.To4(); ip4 != nil {
                if ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
                        return true
                }
                if ip4[0] == 192 && ip4[1] == 0 && ip4[2] == 0 {
                        return true
                }
                if ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19) {
                        return true
                }
        }

        return false
}

func ValidateURLTarget(rawURL string) bool {
        parsed, err := url.Parse(rawURL)
        if err != nil {
                return false
        }
        hostname := parsed.Hostname()
        if hostname == "" {
                return false
        }

        addrs, err := net.LookupHost(hostname)
        if err != nil {
                return false
        }
        if len(addrs) == 0 {
                return false
        }

        for _, addr := range addrs {
                if IsPrivateIP(addr) {
                        return false
                }
        }
        return true
}
