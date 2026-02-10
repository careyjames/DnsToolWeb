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
                c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
                c.Header("Cross-Origin-Opener-Policy", "same-origin")
                c.Header("Cross-Origin-Resource-Policy", "same-origin")

                csp := fmt.Sprintf(
                        "default-src 'self'; "+
                                "script-src 'self' 'nonce-%s'; "+
                                "style-src 'self' 'unsafe-inline'; "+
                                "font-src 'self'; "+
                                "img-src 'self' data: https:; "+
                                "object-src 'none'; "+
                                "connect-src 'self'; "+
                                "frame-ancestors 'none'; "+
                                "base-uri 'self'; "+
                                "form-action 'self'; "+
                                "upgrade-insecure-requests;",
                        nonceStr,
                )
                c.Header("Content-Security-Policy", csp)

                c.Next()
        }
}

func Recovery() gin.HandlerFunc {
        return func(c *gin.Context) {
                defer func() {
                        if err := recover(); err != nil {
                                traceID, _ := c.Get("trace_id")
                                slog.Error("Panic recovered",
                                        "trace_id", traceID,
                                        "error", fmt.Sprintf("%v", err),
                                        "path", c.Request.URL.Path,
                                )
                                c.AbortWithStatus(http.StatusInternalServerError)
                        }
                }()
                c.Next()
        }
}
