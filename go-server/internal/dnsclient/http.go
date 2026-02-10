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
	return &SafeHTTPClient{
		client: &http.Client{
			Timeout: 10 * time.Second,
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
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
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
