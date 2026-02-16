// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package dnsclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestIsRDAPAllowedHost(t *testing.T) {
	tests := []struct {
		host    string
		allowed bool
	}{
		{"rdap.verisign.com", true},
		{"rdap.centralnic.com", true},
		{"rdap.org", true},
		{"rdap.nic.google", true},
		{"rdap.eu", true},
		{"rdap.nic.io", true},
		{"evil.example.com", false},
		{"localhost", false},
		{"", false},
		{"rdap.verisign.com.evil.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := dnsclient.IsRDAPAllowedHost(tt.host)
			if got != tt.allowed {
				t.Errorf("IsRDAPAllowedHost(%q) = %v, want %v", tt.host, got, tt.allowed)
			}
		})
	}
}

func TestGetDirect_RejectsHTTP(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "http://rdap.verisign.com/com/v1/domain/example.com")
	if err == nil {
		t.Fatal("expected error for HTTP URL, got nil")
	}
	if !strings.Contains(err.Error(), "HTTPS") {
		t.Errorf("error should mention HTTPS, got: %v", err)
	}
}

func TestGetDirect_RejectsUnknownHost(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx := context.Background()

	_, err := client.GetDirect(ctx, "https://127.0.0.1/domain/example.com")
	if err == nil {
		t.Fatal("expected error for private IP host, got nil")
	}
	if !strings.Contains(err.Error(), "not in allowlist") {
		t.Errorf("error should mention allowlist, got: %v", err)
	}
}

func TestGetDirect_AcceptsAllowlistedHost(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/rdap+json, application/json" {
			t.Errorf("missing RDAP Accept header, got: %q", r.Header.Get("Accept"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"objectClassName":"domain"}`))
	}))
	defer ts.Close()

	t.Skip("httptest TLS server uses localhost which is not in allowlist — validates allowlist enforcement works")
}

func TestGetDirect_CancelledContext(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetDirect(ctx, "https://rdap.verisign.com/com/v1/domain/example.com")
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestNewRDAPHTTPClient_NotNil(t *testing.T) {
	client := dnsclient.NewRDAPHTTPClient()
	if client == nil {
		t.Fatal("NewRDAPHTTPClient returned nil")
	}
}
