// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package config

import (
        "fmt"
        "os"
        "strings"
)

var (
        Version   = "26.22.7"
        GitCommit = "dev"
        BuildTime = "unknown"
)

type Config struct {
        DatabaseURL        string
        SessionSecret      string
        Port               string
        AppVersion         string
        Testing            bool
        SMTPProbeMode      string
        ProbeAPIURL        string
        ProbeAPIKey        string
        MaintenanceNote    string
        SectionTuning      map[string]string
        GoogleClientID     string
        GoogleClientSecret string
        GoogleRedirectURL  string
        InitialAdminEmail string
        BaseURL            string
        IsDevEnvironment   bool
}

var sectionTuningMap = map[string]string{
        // "email": "Accuracy Tuning",
        // "dane":         "Accuracy Tuning",
        // "brand": "Accuracy Tuning",
        // "securitytxt":  "Accuracy Tuning",
        "ai": "Beta",
        // "secrets":      "Accuracy Tuning",
        // "web-exposure": "Accuracy Tuning",
        "smtp": "Beta",
        // "infra": "Accuracy Tuning",
        // "dnssec":       "Accuracy Tuning",
        // "traffic":      "Accuracy Tuning",
}

func Load() (*Config, error) {
        dbURL := os.Getenv("DATABASE_URL")
        if dbURL == "" {
                return nil, fmt.Errorf("DATABASE_URL environment variable is required")
        }

        sessionSecret := os.Getenv("SESSION_SECRET")
        if sessionSecret == "" {
                return nil, fmt.Errorf("SESSION_SECRET environment variable is required")
        }

        port := os.Getenv("PORT")
        if port == "" {
                port = "5000"
        }

        smtpProbeMode := os.Getenv("SMTP_PROBE_MODE")
        if smtpProbeMode == "" {
                smtpProbeMode = "skip"
        }

        probeAPIURL := os.Getenv("PROBE_API_URL")
        if probeAPIURL != "" && smtpProbeMode == "skip" {
                smtpProbeMode = "remote"
        }

        maintenanceNote := os.Getenv("MAINTENANCE_NOTE")

        tuning := make(map[string]string)
        for k, v := range sectionTuningMap {
                tuning[k] = v
        }
        envTuning := os.Getenv("SECTION_TUNING")
        if envTuning != "" {
                for _, pair := range strings.Split(envTuning, ",") {
                        parts := strings.SplitN(strings.TrimSpace(pair), "=", 2)
                        if len(parts) == 2 {
                                tuning[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
                        }
                }
        }

        baseURLRaw := os.Getenv("BASE_URL")
        baseURL := baseURLRaw
        if baseURL == "" {
                baseURL = "https://dnstool.it-help.tech"
        }
        isDevEnv := baseURLRaw == "" || baseURL != "https://dnstool.it-help.tech"

        googleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
        if googleRedirectURL == "" {
                googleRedirectURL = baseURL + "/auth/callback"
        }

        return &Config{
                DatabaseURL:         dbURL,
                SessionSecret:       sessionSecret,
                Port:                port,
                AppVersion:          Version,
                Testing:             false,
                SMTPProbeMode:       smtpProbeMode,
                ProbeAPIURL:         probeAPIURL,
                ProbeAPIKey:         os.Getenv("PROBE_API_KEY"),
                MaintenanceNote:     maintenanceNote,
                SectionTuning:       tuning,
                GoogleClientID:      os.Getenv("GOOGLE_CLIENT_ID"),
                GoogleClientSecret:  os.Getenv("GOOGLE_CLIENT_SECRET"),
                GoogleRedirectURL:   googleRedirectURL,
                InitialAdminEmail:   strings.TrimSpace(os.Getenv("INITIAL_ADMIN_EMAIL")),
                BaseURL:             baseURL,
                IsDevEnvironment:    isDevEnv,
        }, nil
}
