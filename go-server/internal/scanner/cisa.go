// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package scanner

import (
	"bufio"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const cisaURL = "https://rules.ncats.cyber.dhs.gov/all.txt"

var (
	cisaIPNets []*net.IPNet
	cisaListMu sync.RWMutex
)

func StartCISARefresh() {
	go func() {
		fetchCISAList()
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			fetchCISAList()
		}
	}()
}

func fetchCISAList() {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(cisaURL)
	if err != nil {
		slog.Warn("CISA IP list fetch failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("CISA IP list non-200 response", "status", resp.StatusCode)
		return
	}

	var nets []*net.IPNet
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if !strings.Contains(line, "/") {
			if strings.Contains(line, ":") {
				line += "/128"
			} else {
				line += "/32"
			}
		}

		_, cidr, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		nets = append(nets, cidr)
	}

	if len(nets) > 0 {
		cisaListMu.Lock()
		cisaIPNets = nets
		cisaListMu.Unlock()
		slog.Info("CISA IP list refreshed", "entries", len(nets))
	}
}

func CISAListSize() int {
	cisaListMu.RLock()
	defer cisaListMu.RUnlock()
	return len(cisaIPNets)
}
