// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package middleware_test

import (
        "fmt"
        "net/http"
        "net/http/httptest"
        "net/url"
        "strings"
        "testing"

        "dnstool/go-server/internal/middleware"

        "github.com/gin-gonic/gin"
)

const testSecret = "test-secret-key-for-csrf"

const (
        msgExpect200       = "expected 200, got %d"
        pathSubmit         = "/submit"
        headerContentType  = "Content-Type"
        contentTypeForm    = "application/x-www-form-urlencoded"
        msgExpect403       = "expected 403, got %d"
        testDomainExample  = "example.com"
        msgFirstReqAllowed = "first request should be allowed"
)

func init() {
        gin.SetMode(gin.TestMode)
}

func setupCSRFRouter() (*gin.Engine, *middleware.CSRFMiddleware) {
        csrf := middleware.NewCSRFMiddleware(testSecret)
        router := gin.New()
        router.Use(csrf.Handler())
        return router, csrf
}

func TestCSRFGetRequestSetsToken(t *testing.T) {
        router, _ := setupCSRFRouter()

        var ctxToken string
        router.GET("/form", func(c *gin.Context) {
                ctxToken = middleware.GetCSRFToken(c)
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/form", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf(msgExpect200, w.Code)
        }

        if ctxToken == "" {
                t.Fatal("csrf_token was not set in context")
        }

        cookies := w.Result().Cookies()
        var csrfCookie *http.Cookie
        for _, c := range cookies {
                if c.Name == "_csrf" {
                        csrfCookie = c
                        break
                }
        }
        if csrfCookie == nil {
                t.Fatal("_csrf cookie was not set")
        }
        if csrfCookie.Value == "" {
                t.Fatal("_csrf cookie value is empty")
        }
}

func TestCSRFPostWithoutCookie(t *testing.T) {
        router, _ := setupCSRFRouter()

        router.POST(pathSubmit, func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", pathSubmit, strings.NewReader("csrf_token=sometoken"))
        req.Header.Set(headerContentType, contentTypeForm)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusForbidden {
                t.Fatalf(msgExpect403, w.Code)
        }
}

func TestCSRFPostWithInvalidSignature(t *testing.T) {
        router, _ := setupCSRFRouter()

        router.POST(pathSubmit, func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", pathSubmit, strings.NewReader("csrf_token=faketoken"))
        req.Header.Set(headerContentType, contentTypeForm)
        req.AddCookie(&http.Cookie{
                Name:  "_csrf",
                Value: "faketoken.invalidsignature",
        })
        router.ServeHTTP(w, req)

        if w.Code != http.StatusForbidden {
                t.Fatalf(msgExpect403, w.Code)
        }
}

func TestCSRFPostWithValidToken(t *testing.T) {
        router, _ := setupCSRFRouter()

        var capturedToken string
        router.GET("/form", func(c *gin.Context) {
                capturedToken = middleware.GetCSRFToken(c)
                c.String(http.StatusOK, "ok")
        })
        router.POST(pathSubmit, func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        getW := httptest.NewRecorder()
        getReq := httptest.NewRequest("GET", "/form", nil)
        router.ServeHTTP(getW, getReq)

        var csrfCookieValue string
        for _, c := range getW.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookieValue = c.Value
                        break
                }
        }

        form := url.Values{}
        form.Set("csrf_token", capturedToken)
        postW := httptest.NewRecorder()
        postReq := httptest.NewRequest("POST", pathSubmit, strings.NewReader(form.Encode()))
        postReq.Header.Set(headerContentType, contentTypeForm)
        postReq.AddCookie(&http.Cookie{
                Name:  "_csrf",
                Value: csrfCookieValue,
        })
        router.ServeHTTP(postW, postReq)

        if postW.Code != http.StatusOK {
                t.Fatalf(msgExpect200, postW.Code)
        }
}

func TestCSRFPostWithHeaderToken(t *testing.T) {
        router, _ := setupCSRFRouter()

        var capturedToken string
        router.GET("/form", func(c *gin.Context) {
                capturedToken = middleware.GetCSRFToken(c)
                c.String(http.StatusOK, "ok")
        })
        router.POST(pathSubmit, func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        getW := httptest.NewRecorder()
        getReq := httptest.NewRequest("GET", "/form", nil)
        router.ServeHTTP(getW, getReq)

        var csrfCookieValue string
        for _, c := range getW.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookieValue = c.Value
                        break
                }
        }

        postW := httptest.NewRecorder()
        postReq := httptest.NewRequest("POST", pathSubmit, nil)
        postReq.Header.Set("X-CSRF-Token", capturedToken)
        postReq.AddCookie(&http.Cookie{
                Name:  "_csrf",
                Value: csrfCookieValue,
        })
        router.ServeHTTP(postW, postReq)

        if postW.Code != http.StatusOK {
                t.Fatalf(msgExpect200, postW.Code)
        }
}

func TestCSRFPostTokenMismatch(t *testing.T) {
        router, _ := setupCSRFRouter()

        router.GET("/form", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })
        router.POST(pathSubmit, func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        getW := httptest.NewRecorder()
        getReq := httptest.NewRequest("GET", "/form", nil)
        router.ServeHTTP(getW, getReq)

        var csrfCookieValue string
        for _, c := range getW.Result().Cookies() {
                if c.Name == "_csrf" {
                        csrfCookieValue = c.Value
                        break
                }
        }

        form := url.Values{}
        form.Set("csrf_token", "wrong-token-value")
        postW := httptest.NewRecorder()
        postReq := httptest.NewRequest("POST", pathSubmit, strings.NewReader(form.Encode()))
        postReq.Header.Set(headerContentType, contentTypeForm)
        postReq.AddCookie(&http.Cookie{
                Name:  "_csrf",
                Value: csrfCookieValue,
        })
        router.ServeHTTP(postW, postReq)

        if postW.Code != http.StatusForbidden {
                t.Fatalf(msgExpect403, postW.Code)
        }
}

func TestCSRFAPIRouteExempt(t *testing.T) {
        router, _ := setupCSRFRouter()

        router.POST("/api/something", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("POST", "/api/something", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf("expected 200 for exempt API route, got %d", w.Code)
        }
}

func TestRateLimitAllowsInitial(t *testing.T) {
        limiter := middleware.NewInMemoryRateLimiter()
        result := limiter.CheckAndRecord("192.168.1.1", testDomainExample)

        if !result.Allowed {
                t.Fatalf("expected initial request to be allowed, got blocked with reason: %s", result.Reason)
        }
}

func TestRateLimitBlocksAfterMax(t *testing.T) {
        limiter := middleware.NewInMemoryRateLimiter()

        for i := 0; i < 8; i++ {
                domain := fmt.Sprintf("domain%d.com", i)
                result := limiter.CheckAndRecord("10.0.0.1", domain)
                if !result.Allowed {
                        t.Fatalf("request %d should be allowed, got blocked with reason: %s", i+1, result.Reason)
                }
        }

        result := limiter.CheckAndRecord("10.0.0.1", "domain8.com")
        if result.Allowed {
                t.Fatal("9th request should be blocked")
        }
        if result.Reason != "rate_limit" {
                t.Fatalf("expected reason 'rate_limit', got '%s'", result.Reason)
        }
}

func TestAntiRepeatBlocksSameDomain(t *testing.T) {
        limiter := middleware.NewInMemoryRateLimiter()

        result := limiter.CheckAndRecord("10.0.0.2", testDomainExample)
        if !result.Allowed {
                t.Fatal(msgFirstReqAllowed)
        }

        result = limiter.CheckAndRecord("10.0.0.2", testDomainExample)
        if result.Allowed {
                t.Fatal("repeat request for same domain should be blocked")
        }
        if result.Reason != "anti_repeat" {
                t.Fatalf("expected reason 'anti_repeat', got '%s'", result.Reason)
        }
}

func TestAntiRepeatAllowsDifferentDomain(t *testing.T) {
        limiter := middleware.NewInMemoryRateLimiter()

        result := limiter.CheckAndRecord("10.0.0.3", testDomainExample)
        if !result.Allowed {
                t.Fatal(msgFirstReqAllowed)
        }

        result = limiter.CheckAndRecord("10.0.0.3", "different.com")
        if !result.Allowed {
                t.Fatalf("different domain should be allowed, got blocked with reason: %s", result.Reason)
        }
}

func TestAntiRepeatCaseInsensitive(t *testing.T) {
        limiter := middleware.NewInMemoryRateLimiter()

        result := limiter.CheckAndRecord("10.0.0.4", "Example.COM")
        if !result.Allowed {
                t.Fatal(msgFirstReqAllowed)
        }

        result = limiter.CheckAndRecord("10.0.0.4", testDomainExample)
        if result.Allowed {
                t.Fatal("case-insensitive duplicate should be blocked")
        }
        if result.Reason != "anti_repeat" {
                t.Fatalf("expected reason 'anti_repeat', got '%s'", result.Reason)
        }
}

func TestSecurityHeadersPresent(t *testing.T) {
        router := gin.New()
        router.Use(middleware.RequestContext())
        router.Use(middleware.SecurityHeaders())
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        router.ServeHTTP(w, req)

        if w.Code != http.StatusOK {
                t.Fatalf(msgExpect200, w.Code)
        }

        checks := map[string]string{
                "X-Content-Type-Options":    "nosniff",
                "X-Frame-Options":           "DENY",
                "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        }

        for header, expected := range checks {
                got := w.Header().Get(header)
                if got != expected {
                        t.Errorf("expected %s: %s, got: %s", header, expected, got)
                }
        }

        csp := w.Header().Get("Content-Security-Policy")
        if csp == "" {
                t.Fatal("Content-Security-Policy header is missing")
        }
        if !strings.Contains(csp, "nonce-") {
                t.Error("CSP header does not contain a nonce")
        }
        if strings.Contains(csp, "upgrade-insecure-requests") {
                t.Error("CSP should NOT contain upgrade-insecure-requests for plain HTTP requests")
        }
}

func TestSecurityHeadersUpgradeInsecureHTTPS(t *testing.T) {
        router := gin.New()
        router.Use(middleware.RequestContext())
        router.Use(middleware.SecurityHeaders())
        router.GET("/test", func(c *gin.Context) {
                c.String(http.StatusOK, "ok")
        })

        w := httptest.NewRecorder()
        req := httptest.NewRequest("GET", "/test", nil)
        req.Header.Set("X-Forwarded-Proto", "https")
        router.ServeHTTP(w, req)

        csp := w.Header().Get("Content-Security-Policy")
        if !strings.Contains(csp, "upgrade-insecure-requests") {
                t.Error("CSP should contain upgrade-insecure-requests for HTTPS requests")
        }
}
