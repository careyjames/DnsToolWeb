package middleware

import (
        "context"
        "net/http"
        "time"

        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgxpool"
)

const sessionCookieName = "_dns_session"

func SessionLoader(pool *pgxpool.Pool) gin.HandlerFunc {
        queries := dbq.New(pool)
        return func(c *gin.Context) {
                cookie, err := c.Cookie(sessionCookieName)
                if err != nil || cookie == "" {
                        c.Next()
                        return
                }

                session, err := queries.GetSession(c.Request.Context(), cookie)
                if err != nil {
                        c.Next()
                        return
                }

                c.Set("user_id", session.UserID)
                c.Set("user_email", session.Email)
                c.Set("user_name", session.Name)
                c.Set("user_role", session.Role)
                c.Set("session_id", session.ID)
                c.Set("authenticated", true)

                go func(token string) {
                        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
                        defer cancel()
                        _ = queries.UpdateSessionLastSeen(ctx, token)
                }(cookie)

                c.Next()
        }
}

func RequireAuth() gin.HandlerFunc {
        return func(c *gin.Context) {
                auth, exists := c.Get("authenticated")
                if !exists || auth != true {
                        c.JSON(http.StatusUnauthorized, gin.H{
                                "error": "Authentication required",
                        })
                        c.Abort()
                        return
                }
                c.Next()
        }
}

func RequireAdmin() gin.HandlerFunc {
        return func(c *gin.Context) {
                auth, exists := c.Get("authenticated")
                if !exists || auth != true {
                        c.JSON(http.StatusUnauthorized, gin.H{
                                "error": "Authentication required",
                        })
                        c.Abort()
                        return
                }
                role, _ := c.Get("user_role")
                if role != "admin" {
                        c.JSON(http.StatusForbidden, gin.H{
                                "error": "Administrator access required",
                        })
                        c.Abort()
                        return
                }
                c.Next()
        }
}

func GetAuthTemplateData(c *gin.Context) map[string]any {
        data := map[string]any{}
        if auth, exists := c.Get("authenticated"); exists && auth == true {
                email, _ := c.Get("user_email")
                name, _ := c.Get("user_name")
                role, _ := c.Get("user_role")
                data["Authenticated"] = true
                data["UserEmail"] = email
                data["UserName"] = name
                data["UserRole"] = role
        }
        return data
}
