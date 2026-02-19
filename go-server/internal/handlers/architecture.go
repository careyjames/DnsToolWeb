// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
	"net/http"
	"os"
	"strings"

	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

type MermaidDiagram struct {
	Title   string
	Content string
}

type ArchitectureHandler struct {
	Config *config.Config
}

func NewArchitectureHandler(cfg *config.Config) *ArchitectureHandler {
	return &ArchitectureHandler{Config: cfg}
}

func (h *ArchitectureHandler) Architecture(c *gin.Context) {
	nonce, _ := c.Get("csp_nonce")

	diagrams, err := parseMermaidDiagrams("docs/architecture/SYSTEM_ARCHITECTURE.md")
	if err != nil {
		diagrams = []MermaidDiagram{}
	}

	data := gin.H{
		"AppVersion":      h.Config.AppVersion,
		"MaintenanceNote": h.Config.MaintenanceNote,
		"CspNonce":        nonce,
		"ActivePage":      "architecture",
		"Diagrams":        diagrams,
	}
	mergeAuthData(c, h.Config, data)
	c.HTML(http.StatusOK, "architecture.html", data)
}

func parseMermaidDiagrams(filePath string) ([]MermaidDiagram, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var diagrams []MermaidDiagram
	var currentTitle string
	var currentContent strings.Builder
	inMermaidBlock := false

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Check for section heading (## N. Title)
		if strings.HasPrefix(trimmedLine, "##") && !inMermaidBlock {
			currentTitle = strings.TrimPrefix(trimmedLine, "##")
			currentTitle = strings.TrimSpace(currentTitle)
		}

		// Check for start of mermaid block
		if trimmedLine == "```mermaid" {
			inMermaidBlock = true
			currentContent.Reset()
			continue
		}

		// Check for end of mermaid block
		if trimmedLine == "```" && inMermaidBlock {
			inMermaidBlock = false
			diagram := MermaidDiagram{
				Title:   currentTitle,
				Content: strings.TrimSpace(currentContent.String()),
			}
			diagrams = append(diagrams, diagram)
			continue
		}

		// Collect content inside mermaid block
		if inMermaidBlock {
			if currentContent.Len() > 0 {
				currentContent.WriteString("\n")
			}
			currentContent.WriteString(line)
		}
	}

	return diagrams, nil
}
