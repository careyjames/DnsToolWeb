// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package config

import (
        "fmt"
        "os"
)

type Config struct {
        DatabaseURL    string
        SessionSecret  string
        Port           string
        AppVersion     string
        Testing        bool
        SMTPProbeMode  string
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

        return &Config{
                DatabaseURL:    dbURL,
                SessionSecret:  sessionSecret,
                Port:           port,
                AppVersion:     "26.19.8",
                Testing:        false,
                SMTPProbeMode:  smtpProbeMode,
        }, nil
}
