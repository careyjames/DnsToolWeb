package config

import (
        "fmt"
        "os"
)

type Config struct {
        DatabaseURL   string
        SessionSecret string
        Port          string
        AppVersion    string
        Testing       bool
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

        return &Config{
                DatabaseURL:   dbURL,
                SessionSecret: sessionSecret,
                Port:          port,
                AppVersion:    "26.12.22",
                Testing:       false,
        }, nil
}
