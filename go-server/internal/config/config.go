// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package config

import (
        "fmt"
        "os"
        "strings"
)

type Config struct {
        DatabaseURL     string
        SessionSecret   string
        Port            string
        AppVersion      string
        Testing         bool
        SMTPProbeMode   string
        MaintenanceNote string
        SectionTuning   map[string]string
}

var sectionTuningMap = map[string]string{
        "email": "Accuracy Tuning",
        // "dane":         "Accuracy Tuning",
        "brand": "Accuracy Tuning",
        // "securitytxt":  "Accuracy Tuning",
        "ai":   "Accuracy Tuning",
        // "secrets":      "Accuracy Tuning",
        // "web-exposure": "Accuracy Tuning",
        "smtp": "Accuracy Tuning",
        "infra": "Accuracy Tuning",
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

        return &Config{
                DatabaseURL:     dbURL,
                SessionSecret:   sessionSecret,
                Port:            port,
                AppVersion:      "26.19.38",
                Testing:         false,
                SMTPProbeMode:   smtpProbeMode,
                MaintenanceNote: maintenanceNote,
                SectionTuning:   tuning,
        }, nil
}
