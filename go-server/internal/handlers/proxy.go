package handlers

import (
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const (
        bimiMaxRedirects     = 5
        bimiMaxResponseBytes = 512 * 1024
)

var bimiAllowedContentTypes = map[string]bool{
        "image/svg+xml": true,
        "image/png":     true,
        "image/jpeg":    true,
        "image/gif":     true,
        "image/webp":    true,
}

type ProxyHandler struct{}

func NewProxyHandler() *ProxyHandler {
        return &ProxyHandler{}
}

func (h *ProxyHandler) BIMILogo(c *gin.Context) {
        logoURL := c.Query("url")
        if logoURL == "" {
                c.String(http.StatusBadRequest, "Missing URL parameter")
                return
        }

        parsed, err := url.Parse(logoURL)
        if err != nil {
                c.String(http.StatusBadRequest, "Invalid URL")
                return
        }

        if err := validateParsedURL(parsed); err != nil {
                c.String(http.StatusBadRequest, err.Error())
                return
        }

        if err := checkSSRF(parsed.Hostname()); err != nil {
                c.String(http.StatusBadRequest, err.Error())
                return
        }

        safeURL := buildSafeURL(parsed)

        client := &http.Client{
                Timeout: 5 * time.Second,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                },
        }

        req, _ := http.NewRequestWithContext(c.Request.Context(), "GET", safeURL, nil)
        req.Header.Set("User-Agent", "DNS-Analyzer/1.0 BIMI-Logo-Fetcher")

        resp, err := client.Do(req)
        if err != nil {
                slog.Error("Failed to fetch BIMI logo", "error", err)
                c.String(http.StatusBadGateway, "Failed to fetch logo")
                return
        }
        defer resp.Body.Close()

        resp, err = h.followRedirects(c, client, resp)
        if err != nil {
                return
        }

        body, safeCT, err := validateBIMIResponse(resp)
        if err != nil {
                if ve, ok := err.(*bimiFetchError); ok {
                        c.String(ve.status, ve.msg)
                } else {
                        c.String(http.StatusInternalServerError, "Error reading response")
                }
                return
        }

        c.Header("Cache-Control", "public, max-age=3600")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        c.Header("X-Frame-Options", "DENY")
        c.Data(http.StatusOK, safeCT, body)
}

func validateParsedURL(parsed *url.URL) error {
        if parsed.Scheme != "https" {
                return &validationError{"Only HTTPS URLs allowed"}
        }
        if parsed.Hostname() == "" {
                return &validationError{"Invalid URL"}
        }
        return nil
}

func checkSSRF(hostname string) error {
        ips, err := net.LookupIP(hostname)
        if err != nil {
                return &validationError{"Could not resolve hostname"}
        }
        for _, ip := range ips {
                if dnsclient.IsPrivateIP(ip.String()) {
                        return &validationError{"URL points to a disallowed address"}
                }
        }
        return nil
}

func buildSafeURL(parsed *url.URL) string {
        u := &url.URL{
                Scheme:   "https",
                Host:     parsed.Host,
                Path:     parsed.Path,
                RawQuery: parsed.RawQuery,
                Fragment: parsed.Fragment,
        }
        return u.String()
}

type bimiFetchError struct {
        status int
        msg    string
}

func (e *bimiFetchError) Error() string {
        return e.msg
}

func (h *ProxyHandler) followRedirects(c *gin.Context, client *http.Client, resp *http.Response) (*http.Response, error) {
        redirectCount := 0
        for resp.StatusCode >= 301 && resp.StatusCode <= 308 && redirectCount < bimiMaxRedirects {
                redirectCount++
                redirectURL := resp.Header.Get("Location")
                if redirectURL == "" {
                        c.String(http.StatusBadGateway, "Redirect without Location header")
                        return nil, fmt.Errorf("redirect without location")
                }

                rParsed, err := url.Parse(redirectURL)
                if err != nil {
                        c.String(http.StatusBadRequest, "Invalid redirect URL")
                        return nil, err
                }
                if err := validateParsedURL(rParsed); err != nil {
                        c.String(http.StatusBadRequest, err.Error())
                        return nil, err
                }
                if err := checkSSRF(rParsed.Hostname()); err != nil {
                        c.String(http.StatusBadRequest, err.Error())
                        return nil, err
                }

                resp.Body.Close()
                validatedRedirect := buildSafeURL(rParsed)
                req, _ := http.NewRequestWithContext(c.Request.Context(), "GET", validatedRedirect, nil)
                req.Header.Set("User-Agent", "DNS-Analyzer/1.0 BIMI-Logo-Fetcher")
                resp, err = client.Do(req)
                if err != nil {
                        c.String(http.StatusBadGateway, "Failed to follow redirect")
                        return nil, err
                }
                defer resp.Body.Close()
        }
        return resp, nil
}

func validateBIMIResponse(resp *http.Response) ([]byte, string, error) {
        if resp.StatusCode != 200 {
                return nil, "", &bimiFetchError{http.StatusBadGateway, fmt.Sprintf("Failed to fetch logo: %d", resp.StatusCode)}
        }

        contentType := resp.Header.Get("Content-Type")
        isImage := strings.Contains(strings.ToLower(contentType), "svg") ||
                strings.Contains(strings.ToLower(contentType), "image")
        if !isImage {
                return nil, "", &bimiFetchError{http.StatusBadRequest, "Response is not an image"}
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, bimiMaxResponseBytes+1))
        if err != nil {
                return nil, "", err
        }
        if len(body) > bimiMaxResponseBytes {
                return nil, "", &bimiFetchError{http.StatusBadRequest, "Response too large"}
        }

        safeCT := strings.TrimSpace(strings.Split(strings.ToLower(contentType), ";")[0])
        if !bimiAllowedContentTypes[safeCT] {
                safeCT = "image/svg+xml"
        }
        return body, safeCT, nil
}

type validationError struct {
        msg string
}

func (e *validationError) Error() string {
        return e.msg
}
