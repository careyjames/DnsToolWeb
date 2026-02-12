package main

import (
        "fmt"
        "html/template"
        "log/slog"
        "net/http"
        "os"
        "path/filepath"
        "strings"

        "dnstool/go-server/internal/analyzer"
        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"
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

        database, err := db.Connect(cfg.DatabaseURL)
        if err != nil {
                slog.Error("Failed to connect to database", "error", err)
                os.Exit(1)
        }
        defer database.Close()

        gin.SetMode(gin.ReleaseMode)
        router := gin.New()

        router.Use(middleware.Recovery(cfg.AppVersion))
        router.Use(gzip.Gzip(gzip.DefaultCompression))
        router.Use(middleware.RequestContext())
        router.Use(middleware.SecurityHeaders())

        csrf := middleware.NewCSRFMiddleware(cfg.SessionSecret)
        router.Use(csrf.Handler())

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
                        c.Header(headerCacheControl, "public, max-age=86400")
                }
                fileServer.ServeHTTP(c.Writer, c.Request)
        })

        dnsAnalyzer := analyzer.New()
        slog.Info("DNS analyzer initialized with telemetry")

        homeHandler := handlers.NewHomeHandler(cfg)
        healthHandler := handlers.NewHealthHandler(database, dnsAnalyzer)
        historyHandler := handlers.NewHistoryHandler(database, cfg)
        analysisHandler := handlers.NewAnalysisHandler(database, cfg, dnsAnalyzer)
        statsHandler := handlers.NewStatsHandler(database, cfg)
        compareHandler := handlers.NewCompareHandler(database, cfg)
        exportHandler := handlers.NewExportHandler(database)
        staticHandler := handlers.NewStaticHandler(staticDir)
        proxyHandler := handlers.NewProxyHandler()

        router.GET("/", homeHandler.Index)
        router.GET("/go/health", healthHandler.HealthCheck)

        router.GET("/robots.txt", staticHandler.RobotsTxt)
        router.GET("/sitemap.xml", staticHandler.SitemapXML)
        router.GET("/llms.txt", staticHandler.LLMsTxt)
        router.GET("/llms-full.txt", staticHandler.LLMsFullTxt)
        router.GET("/manifest.json", staticHandler.ManifestJSON)
        router.GET("/sw.js", staticHandler.ServiceWorker)

        router.GET("/analyze", analysisHandler.Analyze)
        router.POST("/analyze", middleware.AnalyzeRateLimit(rateLimiter), analysisHandler.Analyze)

        router.GET("/history", historyHandler.History)

        router.GET("/analysis/:id", analysisHandler.ViewAnalysis)
        router.GET("/analysis/:id/view", analysisHandler.ViewAnalysisStatic)

        router.GET("/stats", statsHandler.Stats)
        router.GET("/statistics", statsHandler.StatisticsRedirect)

        router.GET("/compare", compareHandler.Compare)

        router.GET("/export/json", exportHandler.ExportJSON)

        router.GET("/api/analysis/:id", analysisHandler.APIAnalysis)
        router.GET("/api/subdomains/*domain", analysisHandler.APISubdomains)
        router.GET("/api/health", healthHandler.HealthCheck)

        router.GET("/proxy/bimi-logo", proxyHandler.BIMILogo)

        investigateHandler := handlers.NewInvestigateHandler(cfg, dnsAnalyzer)
        router.GET("/investigate", investigateHandler.InvestigatePage)
        router.POST("/investigate", middleware.AnalyzeRateLimit(rateLimiter), investigateHandler.Investigate)

        router.NoRoute(func(c *gin.Context) {
                nonce, _ := c.Get("csp_nonce")
                csrfToken, _ := c.Get("csrf_token")
                c.HTML(http.StatusNotFound, "index.html", gin.H{
                        "AppVersion": cfg.AppVersion,
                        "CspNonce":   nonce,
                        "CsrfToken":  csrfToken,
                        "ActivePage": "home",
                })
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
