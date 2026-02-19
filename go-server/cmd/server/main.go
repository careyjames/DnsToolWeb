// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package main

import (
        "fmt"
        "html/template"
        "log/slog"
        "net/http"
        "os"
        "path/filepath"
        "strings"
        "time"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
        "dnstool/go-server/internal/dnsclient"
        "dnstool/go-server/internal/handlers"
        "dnstool/go-server/internal/middleware"
        tmplFuncs "dnstool/go-server/internal/templates"

        "github.com/gin-contrib/gzip"
        "github.com/gin-gonic/gin"
)

const headerCacheControl = "Cache-Control"

func main() {
        slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
                Level: slog.LevelDebug,
        })))

        cfg, err := config.Load()
        if err != nil {
                slog.Error("Failed to load config", "error", err)
                os.Exit(1)
        }

        dnsclient.SetUserAgentVersion(cfg.AppVersion)

        database, err := db.Connect(cfg.DatabaseURL)
        if err != nil {
                slog.Error("Failed to connect to database", "error", err)
                os.Exit(1)
        }
        defer database.Close()

        gin.SetMode(gin.ReleaseMode)
        router := gin.New()
        router.SetTrustedProxies(nil)
        slog.Info("Trusted proxies disabled — using direct connection IP for rate limiting")

        router.Use(middleware.Recovery(cfg.AppVersion))
        router.Use(gzip.Gzip(gzip.DefaultCompression))
        router.Use(middleware.RequestContext())
        router.Use(middleware.SecurityHeaders())

        csrf := middleware.NewCSRFMiddleware(cfg.SessionSecret)
        router.Use(csrf.Handler())

        router.Use(middleware.SessionLoader(database.Pool))

        rateLimiter := middleware.NewInMemoryRateLimiter()
        slog.Info("Rate limiter initialized", "backend", "in-memory", "max_requests", middleware.RateLimitMaxRequests, "window_seconds", middleware.RateLimitWindow)

        templatesDir := findTemplatesDir()
        tmpl := template.Must(
                template.New("").Funcs(tmplFuncs.FuncMap()).ParseGlob(filepath.Join(templatesDir, "*.html")),
        )
        router.SetHTMLTemplate(tmpl)

        staticDir := findStaticDir()
        staticFS := http.Dir(staticDir)
        fileServer := http.StripPrefix("/static", http.FileServer(staticFS))
        router.GET("/static/*filepath", func(c *gin.Context) {
                fp := c.Param("filepath")
                if strings.HasSuffix(fp, ".css") || strings.HasSuffix(fp, ".js") ||
                        strings.HasSuffix(fp, ".woff2") || strings.HasSuffix(fp, ".woff") ||
                        strings.HasSuffix(fp, ".png") || strings.HasSuffix(fp, ".ico") ||
                        strings.HasSuffix(fp, ".svg") || strings.HasSuffix(fp, ".jpg") {
                        if strings.Contains(fp, "?v=") || strings.Contains(c.Request.URL.RawQuery, "v=") {
                                c.Header(headerCacheControl, "public, max-age=31536000, immutable")
                        } else {
                                c.Header(headerCacheControl, "public, max-age=86400")
                        }
                }
                fileServer.ServeHTTP(c.Writer, c.Request)
        })
        router.HEAD("/static/*filepath", func(c *gin.Context) {
                fp := c.Param("filepath")
                if strings.HasSuffix(fp, ".css") || strings.HasSuffix(fp, ".js") ||
                        strings.HasSuffix(fp, ".woff2") || strings.HasSuffix(fp, ".woff") ||
                        strings.HasSuffix(fp, ".png") || strings.HasSuffix(fp, ".ico") ||
                        strings.HasSuffix(fp, ".svg") || strings.HasSuffix(fp, ".jpg") {
                        if strings.Contains(fp, "?v=") || strings.Contains(c.Request.URL.RawQuery, "v=") {
                                c.Header(headerCacheControl, "public, max-age=31536000, immutable")
                        } else {
                                c.Header(headerCacheControl, "public, max-age=86400")
                        }
                }
                fileServer.ServeHTTP(c.Writer, c.Request)
        })

        dnsAnalyzer := analyzer.New()
        dnsAnalyzer.SMTPProbeMode = cfg.SMTPProbeMode
        dnsAnalyzer.ProbeAPIURL = cfg.ProbeAPIURL
        slog.Info("DNS analyzer initialized with telemetry", "smtp_probe_mode", cfg.SMTPProbeMode, "probe_api_url", cfg.ProbeAPIURL)

        analyzer.InitIETFMetadata()
        analyzer.ScheduleRFCRefresh()

        dnsHistoryCache := analyzer.NewDNSHistoryCache(24 * time.Hour)
        slog.Info("DNS history cache initialized", "ttl", "24h")

        homeHandler := handlers.NewHomeHandler(cfg)
        healthHandler := handlers.NewHealthHandler(database, dnsAnalyzer)
        historyHandler := handlers.NewHistoryHandler(database, cfg)
        analysisHandler := handlers.NewAnalysisHandler(database, cfg, dnsAnalyzer, dnsHistoryCache)
        statsHandler := handlers.NewStatsHandler(database, cfg)
        compareHandler := handlers.NewCompareHandler(database, cfg)
        exportHandler := handlers.NewExportHandler(database)
        staticHandler := handlers.NewStaticHandler(staticDir, cfg.AppVersion)
        proxyHandler := handlers.NewProxyHandler()

        router.GET("/", homeHandler.Index)
        router.GET("/go/health", healthHandler.HealthCheck)

        router.GET("/.well-known/security.txt", staticHandler.SecurityTxt)
        router.GET("/security.txt", staticHandler.SecurityTxt)
        router.GET("/robots.txt", staticHandler.RobotsTxt)
        router.GET("/sitemap.xml", staticHandler.SitemapXML)
        router.GET("/llms.txt", staticHandler.LLMsTxt)
        router.GET("/llms-full.txt", staticHandler.LLMsFullTxt)
        router.GET("/.well-known/llms.txt", staticHandler.LLMsTxt)
        router.GET("/.well-known/llms-full.txt", staticHandler.LLMsFullTxt)
        router.GET("/manifest.json", staticHandler.ManifestJSON)
        router.GET("/sw.js", staticHandler.ServiceWorker)

        router.GET("/analyze", analysisHandler.Analyze)
        router.POST("/analyze", middleware.AnalyzeRateLimit(rateLimiter), analysisHandler.Analyze)

        router.GET("/history", historyHandler.History)

        dossierHandler := handlers.NewDossierHandler(database, cfg)
        router.GET("/dossier", dossierHandler.Dossier)

        router.GET("/analysis/:id", analysisHandler.ViewAnalysis)
        router.GET("/analysis/:id/view", analysisHandler.ViewAnalysisStatic)
        router.GET("/analysis/:id/executive", analysisHandler.ViewAnalysisExecutive)

        router.GET("/stats", statsHandler.Stats)
        router.GET("/statistics", statsHandler.StatisticsRedirect)

        router.GET("/compare", compareHandler.Compare)

        adminHandler := handlers.NewAdminHandler(database, cfg)
        router.GET("/admin", middleware.RequireAdmin(), adminHandler.Dashboard)

        router.GET("/export/json", middleware.RequireAdmin(), exportHandler.ExportJSON)
        router.GET("/export/subdomains", analysisHandler.ExportSubdomainsCSV)

        router.GET("/api/analysis/:id", analysisHandler.APIAnalysis)
        router.GET("/api/subdomains/*domain", analysisHandler.APISubdomains)
        router.GET("/api/dns-history", analysisHandler.APIDNSHistory)
        router.GET("/api/health", healthHandler.HealthCheck)

        router.GET("/proxy/bimi-logo", proxyHandler.BIMILogo)

        investigateHandler := handlers.NewInvestigateHandler(cfg, dnsAnalyzer)
        router.GET("/investigate", investigateHandler.InvestigatePage)
        router.POST("/investigate", middleware.AnalyzeRateLimit(rateLimiter), investigateHandler.Investigate)

        emailHeaderHandler := handlers.NewEmailHeaderHandler(cfg)
        router.GET("/email-header", emailHeaderHandler.EmailHeaderPage)
        router.POST("/email-header", middleware.AnalyzeRateLimit(rateLimiter), emailHeaderHandler.AnalyzeEmailHeader)

        sourcesHandler := handlers.NewSourcesHandler(cfg)
        router.GET("/sources", sourcesHandler.Sources)

        architectureHandler := handlers.NewArchitectureHandler(cfg)
        router.GET("/architecture", architectureHandler.Architecture)

        changelogHandler := handlers.NewChangelogHandler(cfg)
        router.GET("/changelog", changelogHandler.Changelog)

        faqHandler := handlers.NewFAQHandler(cfg)
        router.GET("/faq/subdomains", faqHandler.SubdomainDiscovery)

        securityPolicyHandler := handlers.NewSecurityPolicyHandler(cfg)
        router.GET("/security-policy", securityPolicyHandler.SecurityPolicy)

        brandColorsHandler := handlers.NewBrandColorsHandler(cfg)
        router.GET("/brand-colors", brandColorsHandler.BrandColors)

        authHandler := handlers.NewAuthHandler(cfg, database.Pool)
        if cfg.GoogleClientID != "" {
                authRL := middleware.AuthRateLimit(rateLimiter)
                router.GET("/auth/login", authRL, authHandler.Login)
                router.GET("/auth/callback", authRL, authHandler.Callback)
                router.GET("/auth/logout", authHandler.Logout)
        }

        router.NoRoute(func(c *gin.Context) {
                nonce, _ := c.Get("csp_nonce")
                csrfToken, _ := c.Get("csrf_token")
                data := gin.H{
                        "AppVersion": cfg.AppVersion,
                        "CspNonce":   nonce,
                        "CsrfToken":  csrfToken,
                        "ActivePage": "home",
                }
                for k, v := range middleware.GetAuthTemplateData(c) {
                        data[k] = v
                }
                if cfg.GoogleClientID != "" {
                        data["GoogleAuthEnabled"] = true
                }
                c.HTML(http.StatusNotFound, "index.html", data)
        })

        addr := fmt.Sprintf("0.0.0.0:%s", cfg.Port)
        slog.Info("Starting Go DNS Tool server", "address", addr, "version", cfg.AppVersion)

        if err := router.Run(addr); err != nil {
                slog.Error("Server failed to start", "error", err)
                os.Exit(1)
        }
}

func findTemplatesDir() string {
        candidates := []string{
                "go-server/templates",
                "templates",
                "../templates",
        }
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        return c
                }
        }
        slog.Warn("Templates directory not found, using default")
        return "templates"
}

func findStaticDir() string {
        candidates := []string{
                "static",
                "go-server/static",
                "../static",
        }
        for _, c := range candidates {
                if info, err := os.Stat(c); err == nil && info.IsDir() {
                        return c
                }
        }
        slog.Warn("Static directory not found, using default")
        return "static"
}
