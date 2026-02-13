// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under AGPL-3.0 — See LICENSE for terms.
package dnsclient_test

import (
	"testing"

	"dnstool/go-server/internal/dnsclient"
)

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.1.100", true},
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"100.127.255.255", true},
		{"192.0.0.1", true},
		{"198.18.0.1", true},
		{"198.19.255.255", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},
		{"172.32.0.1", false},
		{"100.128.0.1", false},
		{"198.20.0.1", false},
		{"192.0.1.1", false},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got := dnsclient.IsPrivateIP(tt.ip)
			if got != tt.private {
				t.Errorf("IsPrivateIP(%q) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}
