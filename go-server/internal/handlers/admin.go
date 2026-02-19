// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "context"
        "fmt"
        "log/slog"
        "net/http"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
)

type AdminHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewAdminHandler(database *db.Database, cfg *config.Config) *AdminHandler {
        return &AdminHandler{DB: database, Config: cfg}
}

type AdminUser struct {
        ID          int32
        Email       string
        Name        string
        Role        string
        CreatedAt   string
        LastLoginAt string
}

type AdminAnalysis struct {
        ID               int32
        Domain           string
        Success          bool
        Duration         string
        CreatedAt        string
        CountryCode      string
        Private          bool
        HasUserSelectors bool
}

type AdminStats struct {
        TotalUsers      int64
        TotalAnalyses   int64
        UniqueDomainsCount int64
        PrivateAnalyses int64
        TotalSessions   int64
        ActiveSessions  int64
}

type AdminICAERun struct {
        ID          int32
        AppVersion  string
        TotalCases  int32
        TotalPassed int32
        TotalFailed int32
        DurationMs  int32
        CreatedAt   string
}

func (h *AdminHandler) Dashboard(c *gin.Context) {
        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")
        ctx := c.Request.Context()

        users := h.fetchUsers(ctx)
        recentAnalyses := h.fetchRecentAnalyses(ctx)
        stats := h.fetchStats(ctx)
        icaeRuns := h.fetchICAERuns(ctx)

        data := gin.H{
                "AppVersion":      h.Config.AppVersion,
                "MaintenanceNote": h.Config.MaintenanceNote,
                "CspNonce":        nonce,
                "CsrfToken":       csrfToken,
                "ActivePage":      "admin",
                "Users":           users,
                "RecentAnalyses":  recentAnalyses,
                "Stats":           stats,
                "ICAERuns":        icaeRuns,
        }
        mergeAuthData(c, h.Config, data)
        c.HTML(http.StatusOK, "admin.html", data)
}

func (h *AdminHandler) fetchUsers(ctx context.Context) []AdminUser {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT id, email, name, role, created_at, COALESCE(last_login_at, created_at)
                 FROM users ORDER BY last_login_at DESC NULLS LAST`)
        if err != nil {
                slog.Error("Admin: failed to fetch users", "error", err)
                return nil
        }
        defer rows.Close()

        var users []AdminUser
        for rows.Next() {
                var u AdminUser
                var createdAt, lastLoginAt time.Time
                if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.Role, &createdAt, &lastLoginAt); err != nil {
                        continue
                }
                u.CreatedAt = createdAt.Format("2006-01-02 15:04")
                u.LastLoginAt = lastLoginAt.Format("2006-01-02 15:04")
                users = append(users, u)
        }
        return users
}

func (h *AdminHandler) fetchRecentAnalyses(ctx context.Context) []AdminAnalysis {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT id, domain, analysis_success, analysis_duration, created_at,
                        COALESCE(country_code, ''), private, has_user_selectors
                 FROM domain_analyses
                 ORDER BY created_at DESC LIMIT 25`)
        if err != nil {
                slog.Error("Admin: failed to fetch analyses", "error", err)
                return nil
        }
        defer rows.Close()

        var analyses []AdminAnalysis
        for rows.Next() {
                var a AdminAnalysis
                var success *bool
                var duration *float64
                var createdAt time.Time
                if err := rows.Scan(&a.ID, &a.Domain, &success, &duration, &createdAt,
                        &a.CountryCode, &a.Private, &a.HasUserSelectors); err != nil {
                        continue
                }
                if success != nil {
                        a.Success = *success
                }
                if duration != nil {
                        a.Duration = fmt.Sprintf("%.1fs", *duration)
                } else {
                        a.Duration = "—"
                }
                a.CreatedAt = createdAt.Format("2006-01-02 15:04")
                analyses = append(analyses, a)
        }
        return analyses
}

func (h *AdminHandler) fetchStats(ctx context.Context) AdminStats {
        var s AdminStats
        _ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&s.TotalUsers)
        _ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM domain_analyses`).Scan(&s.TotalAnalyses)
        _ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(DISTINCT domain) FROM domain_analyses`).Scan(&s.UniqueDomainsCount)
        _ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM domain_analyses WHERE private = TRUE`).Scan(&s.PrivateAnalyses)
        _ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&s.TotalSessions)
        _ = h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM sessions WHERE expires_at > NOW()`).Scan(&s.ActiveSessions)
        return s
}

func (h *AdminHandler) fetchICAERuns(ctx context.Context) []AdminICAERun {
        rows, err := h.DB.Pool.Query(ctx,
                `SELECT id, app_version, total_cases, total_passed, total_failed, duration_ms, created_at
                 FROM ice_test_runs ORDER BY created_at DESC LIMIT 10`)
        if err != nil {
                slog.Error("Admin: failed to fetch ICAE runs", "error", err)
                return nil
        }
        defer rows.Close()

        var runs []AdminICAERun
        for rows.Next() {
                var r AdminICAERun
                var createdAt time.Time
                if err := rows.Scan(&r.ID, &r.AppVersion, &r.TotalCases, &r.TotalPassed,
                        &r.TotalFailed, &r.DurationMs, &createdAt); err != nil {
                        continue
                }
                r.CreatedAt = createdAt.Format("2006-01-02 15:04")
                runs = append(runs, r)
        }
        return runs
}
