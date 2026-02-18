// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package middleware

import (
        "context"
        "crypto/rand"
        "encoding/base64"
        "fmt"
        "log/slog"
        "net/http"
        "time"

        "github.com/gin-gonic/gin"
        "github.com/google/uuid"
)

type contextKey string

const (
        CSPNonceKey contextKey = "csp_nonce"
        TraceIDKey  contextKey = "trace_id"
)

func generateNonce() string {
        b := make([]byte, 16)
        _, _ = rand.Read(b)
        return base64.URLEncoding.EncodeToString(b)
}

func RequestContext() gin.HandlerFunc {
        return func(c *gin.Context) {
                nonce := generateNonce()
                traceID := uuid.New().String()[:8]
                start := time.Now()

                c.Set("csp_nonce", nonce)
                c.Set("trace_id", traceID)
                c.Set("request_start", start)

                ctx := context.WithValue(c.Request.Context(), CSPNonceKey, nonce)
                ctx = context.WithValue(ctx, TraceIDKey, traceID)
                c.Request = c.Request.WithContext(ctx)

                c.Next()

                duration := time.Since(start)
                slog.Info("Request completed",
                        "trace_id", traceID,
                        "method", c.Request.Method,
                        "path", c.Request.URL.Path,
                        "status", c.Writer.Status(),
                        "duration_ms", fmt.Sprintf("%.1f", float64(duration.Microseconds())/1000.0),
                )
        }
}

func SecurityHeaders() gin.HandlerFunc {
        return func(c *gin.Context) {
                nonce, _ := c.Get("csp_nonce")
                nonceStr, _ := nonce.(string)

                c.Header("X-Content-Type-Options", "nosniff")
                c.Header("X-Frame-Options", "DENY")
                c.Header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
                c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
                c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), midi=(), screen-wake-lock=(), xr-spatial-tracking=(), interest-cohort=(), browsing-topics=()")
                c.Header("Cross-Origin-Opener-Policy", "same-origin")
                c.Header("Cross-Origin-Resource-Policy", "same-origin")
                c.Header("X-Permitted-Cross-Domain-Policies", "none")

                upgradeDirective := ""
                if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
                        upgradeDirective = "upgrade-insecure-requests;"
                }

                csp := fmt.Sprintf(
                        "default-src 'none'; "+
                                "script-src 'self' 'nonce-%s'; "+
                                "style-src 'self' 'nonce-%s'; "+
                                "font-src 'self'; "+
                                "img-src 'self' data: https:; "+
                                "connect-src 'self'; "+
                                "frame-ancestors 'none'; "+
                                "base-uri 'none'; "+
                                "form-action 'self'; "+
                                "manifest-src 'self'; "+
                                "object-src 'none'; "+
                                "frame-src 'none'; "+
                                "worker-src 'self'; "+
                                "%s",
                        nonceStr, nonceStr, upgradeDirective,
                )
                c.Header("Content-Security-Policy", csp)

                c.Next()
        }
}

func Recovery(appVersion string) gin.HandlerFunc {
        return func(c *gin.Context) {
                defer func() {
                        if err := recover(); err != nil {
                                traceID, _ := c.Get("trace_id")
                                slog.Error("Panic recovered",
                                        "trace_id", traceID,
                                        "error", fmt.Sprintf("%v", err),
                                        "path", c.Request.URL.Path,
                                )
                                nonce, _ := c.Get("csp_nonce")
                                csrfToken, _ := c.Get("csrf_token")
                                type flashMsg struct {
                                        Category string
                                        Message  string
                                }
                                c.HTML(http.StatusInternalServerError, "index.html", gin.H{
                                        "AppVersion":    appVersion,
                                        "CspNonce":      nonce,
                                        "CsrfToken":     csrfToken,
                                        "ActivePage":    "home",
                                        "FlashMessages": []flashMsg{{Category: "danger", Message: "An internal error occurred. Please try again."}},
                                })
                                c.Abort()
                        }
                }()
                c.Next()
        }
}
