package handlers

import (
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

type StaticHandler struct {
	StaticDir string
}

func NewStaticHandler(staticDir string) *StaticHandler {
	return &StaticHandler{StaticDir: staticDir}
}

func (h *StaticHandler) RobotsTxt(c *gin.Context) {
	c.File(filepath.Join(h.StaticDir, "robots.txt"))
}

func (h *StaticHandler) LLMsTxt(c *gin.Context) {
	c.File(filepath.Join(h.StaticDir, "llms.txt"))
}

func (h *StaticHandler) LLMsFullTxt(c *gin.Context) {
	c.File(filepath.Join(h.StaticDir, "llms-full.txt"))
}

func (h *StaticHandler) ManifestJSON(c *gin.Context) {
	c.Header("Content-Type", "application/manifest+json")
	c.File(filepath.Join(h.StaticDir, "manifest.json"))
}

func (h *StaticHandler) ServiceWorker(c *gin.Context) {
	c.Header("Content-Type", "application/javascript")
	c.File(filepath.Join(h.StaticDir, "sw.js"))
}

func (h *StaticHandler) SitemapXML(c *gin.Context) {
	today := time.Now().Format("2006-01-02")

	pages := []struct {
		Loc        string
		Changefreq string
		Priority   string
	}{
		{"https://dnstool.it-help.tech/", "weekly", "1.0"},
		{"https://dnstool.it-help.tech/history", "daily", "0.6"},
		{"https://dnstool.it-help.tech/stats", "daily", "0.5"},
	}

	xml := `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
	xml += `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n"
	for _, page := range pages {
		xml += "  <url>\n"
		xml += fmt.Sprintf("    <loc>%s</loc>\n", page.Loc)
		xml += fmt.Sprintf("    <lastmod>%s</lastmod>\n", today)
		xml += fmt.Sprintf("    <changefreq>%s</changefreq>\n", page.Changefreq)
		xml += fmt.Sprintf("    <priority>%s</priority>\n", page.Priority)
		xml += "  </url>\n"
	}
	xml += "</urlset>\n"

	c.Data(http.StatusOK, "application/xml", []byte(xml))
}
