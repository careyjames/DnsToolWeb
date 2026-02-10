package main

import (
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"path/filepath"

	"dnstool/internal/config"
	"dnstool/internal/db"
	"dnstool/internal/handlers"
	"dnstool/internal/middleware"
	tmplFuncs "dnstool/internal/templates"

	"github.com/gin-gonic/gin"
)

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

	router.Use(middleware.Recovery())
	router.Use(middleware.RequestContext())
	router.Use(middleware.SecurityHeaders())

	templatesDir := findTemplatesDir()
	tmpl := template.Must(
		template.New("").Funcs(tmplFuncs.FuncMap()).ParseGlob(filepath.Join(templatesDir, "*.html")),
	)
	router.SetHTMLTemplate(tmpl)

	staticDir := findStaticDir()
	router.Static("/static", staticDir)

	homeHandler := handlers.NewHomeHandler(cfg)
	healthHandler := handlers.NewHealthHandler(database)

	router.GET("/", homeHandler.Index)
	router.GET("/go/health", healthHandler.HealthCheck)

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
