package handlers

import (
        "crypto/rand"
        "crypto/sha256"
        "encoding/base64"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
        "github.com/jackc/pgx/v5/pgxpool"
)

const (
        googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
        googleTokenURL    = "https://oauth2.googleapis.com/token"
        googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
        oauthStateCookie  = "_oauth_state"
        oauthCVCookie     = "_oauth_cv"
        sessionCookieName = "_dns_session"
        sessionMaxAge     = 30 * 24 * 60 * 60
)

type AuthHandler struct {
        Config  *config.Config
        Pool    *pgxpool.Pool
        Queries *dbq.Queries
}

func NewAuthHandler(cfg *config.Config, pool *pgxpool.Pool) *AuthHandler {
        return &AuthHandler{
                Config:  cfg,
                Pool:    pool,
                Queries: dbq.New(pool),
        }
}

func generateRandomBase64URL(n int) (string, error) {
        b := make([]byte, n)
        if _, err := rand.Read(b); err != nil {
                return "", err
        }
        return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateSessionID() (string, error) {
        b := make([]byte, 32)
        if _, err := rand.Read(b); err != nil {
                return "", err
        }
        return hex.EncodeToString(b), nil
}

func computeCodeChallenge(verifier string) string {
        h := sha256.Sum256([]byte(verifier))
        return base64.RawURLEncoding.EncodeToString(h[:])
}

func (h *AuthHandler) Login(c *gin.Context) {
        state, err := generateRandomBase64URL(32)
        if err != nil {
                slog.Error("Failed to generate OAuth state", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        codeVerifier, err := generateRandomBase64URL(48)
        if err != nil {
                slog.Error("Failed to generate PKCE code verifier", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        codeChallenge := computeCodeChallenge(codeVerifier)

        c.SetCookie(oauthStateCookie, state, 600, "/", "", true, true)
        c.SetSameSite(http.SameSiteLaxMode)
        c.SetCookie(oauthCVCookie, codeVerifier, 600, "/", "", true, true)

        params := url.Values{
                "client_id":             {h.Config.GoogleClientID},
                "redirect_uri":          {h.Config.GoogleRedirectURL},
                "response_type":         {"code"},
                "scope":                 {"openid email profile"},
                "state":                 {state},
                "code_challenge":        {codeChallenge},
                "code_challenge_method": {"S256"},
                "access_type":           {"online"},
                "prompt":                {"select_account"},
        }

        authURL := googleAuthURL + "?" + params.Encode()
        c.Redirect(http.StatusFound, authURL)
}

func (h *AuthHandler) Callback(c *gin.Context) {
        stateCookie, err := c.Cookie(oauthStateCookie)
        if err != nil || stateCookie == "" {
                slog.Warn("OAuth callback: missing state cookie")
                c.Redirect(http.StatusFound, "/")
                return
        }

        stateParam := c.Query("state")
        if stateParam == "" || stateParam != stateCookie {
                slog.Warn("OAuth callback: state mismatch")
                c.Redirect(http.StatusFound, "/")
                return
        }

        codeVerifier, err := c.Cookie(oauthCVCookie)
        if err != nil || codeVerifier == "" {
                slog.Warn("OAuth callback: missing code verifier cookie")
                c.Redirect(http.StatusFound, "/")
                return
        }

        code := c.Query("code")
        if code == "" {
                slog.Warn("OAuth callback: missing authorization code")
                c.Redirect(http.StatusFound, "/")
                return
        }

        tokenData, err := h.exchangeCode(code, codeVerifier)
        if err != nil {
                slog.Error("OAuth callback: token exchange failed", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        if err := h.validateIDTokenClaims(tokenData); err != nil {
                slog.Error("OAuth callback: ID token validation failed", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        accessToken, ok := tokenData["access_token"].(string)
        if !ok || accessToken == "" {
                slog.Error("OAuth callback: no access_token in response")
                c.Redirect(http.StatusFound, "/")
                return
        }

        userInfo, err := h.fetchUserInfo(accessToken)
        if err != nil {
                slog.Error("OAuth callback: failed to fetch user info", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        sub, _ := userInfo["sub"].(string)
        email, _ := userInfo["email"].(string)
        name, _ := userInfo["name"].(string)
        emailVerified, _ := userInfo["email_verified"].(bool)

        if sub == "" || email == "" || !emailVerified {
                slog.Error("OAuth callback: missing sub/email or email not verified",
                        "sub_present", sub != "",
                        "email_present", email != "",
                        "email_verified", emailVerified,
                )
                c.Redirect(http.StatusFound, "/")
                return
        }

        ctx := c.Request.Context()

        role := "user"
        if h.Config.InitialAdminEmail != "" && strings.EqualFold(email, h.Config.InitialAdminEmail) {
                adminCount, countErr := h.Queries.CountAdminUsers(ctx)
                if countErr != nil {
                        slog.Error("Failed to count admin users", "error", countErr)
                } else if adminCount == 0 {
                        role = "admin"
                        slog.Warn("AUDIT: Admin bootstrap triggered",
                                "email", email,
                                "reason", "zero_admin_users",
                                "initial_admin_email", h.Config.InitialAdminEmail,
                        )
                }
        }
        user, err := h.Queries.UpsertUser(ctx, dbq.UpsertUserParams{
                Email:     email,
                Name:      name,
                GoogleSub: sub,
                Role:      role,
        })
        if err != nil {
                slog.Error("OAuth callback: failed to upsert user", "error", err, "email", email)
                c.Redirect(http.StatusFound, "/")
                return
        }

        sessionID, err := generateSessionID()
        if err != nil {
                slog.Error("OAuth callback: failed to generate session ID", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        expiresAt := time.Now().Add(30 * 24 * time.Hour)
        err = h.Queries.CreateSession(ctx, dbq.CreateSessionParams{
                ID:     sessionID,
                UserID: user.ID,
                ExpiresAt: pgtype.Timestamp{
                        Time:  expiresAt,
                        Valid: true,
                },
        })
        if err != nil {
                slog.Error("OAuth callback: failed to create session", "error", err)
                c.Redirect(http.StatusFound, "/")
                return
        }

        c.SetCookie(sessionCookieName, sessionID, sessionMaxAge, "/", "", true, true)
        c.SetCookie(oauthStateCookie, "", -1, "/", "", true, true)
        c.SetCookie(oauthCVCookie, "", -1, "/", "", true, true)

        slog.Info("User authenticated", "email", email, "role", user.Role, "user_id", user.ID)
        c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) Logout(c *gin.Context) {
        cookie, err := c.Cookie(sessionCookieName)
        if err == nil && cookie != "" {
                _ = h.Queries.DeleteSession(c.Request.Context(), cookie)
        }

        c.SetCookie(sessionCookieName, "", -1, "/", "", true, true)
        c.Redirect(http.StatusFound, "/")
}

func (h *AuthHandler) validateIDTokenClaims(tokenData map[string]any) error {
        idTokenStr, ok := tokenData["id_token"].(string)
        if !ok || idTokenStr == "" {
                return nil
        }

        parts := strings.SplitN(idTokenStr, ".", 3)
        if len(parts) != 3 {
                return fmt.Errorf("malformed id_token: expected 3 parts, got %d", len(parts))
        }

        payload, err := base64.RawURLEncoding.DecodeString(parts[1])
        if err != nil {
                return fmt.Errorf("decoding id_token payload: %w", err)
        }

        var claims map[string]any
        if err := json.Unmarshal(payload, &claims); err != nil {
                return fmt.Errorf("parsing id_token claims: %w", err)
        }

        iss, _ := claims["iss"].(string)
        if iss != "https://accounts.google.com" && iss != "accounts.google.com" {
                return fmt.Errorf("invalid issuer: %s", iss)
        }

        aud, _ := claims["aud"].(string)
        if aud != h.Config.GoogleClientID {
                return fmt.Errorf("invalid audience: %s", aud)
        }

        exp, _ := claims["exp"].(float64)
        if exp > 0 && time.Now().Unix() > int64(exp) {
                return fmt.Errorf("id_token expired at %v", time.Unix(int64(exp), 0))
        }

        return nil
}

func (h *AuthHandler) exchangeCode(code, codeVerifier string) (map[string]any, error) {
        data := url.Values{
                "code":          {code},
                "client_id":     {h.Config.GoogleClientID},
                "client_secret": {h.Config.GoogleClientSecret},
                "redirect_uri":  {h.Config.GoogleRedirectURL},
                "grant_type":    {"authorization_code"},
                "code_verifier": {codeVerifier},
        }

        resp, err := http.PostForm(googleTokenURL, data)
        if err != nil {
                return nil, fmt.Errorf("token request failed: %w", err)
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        if err != nil {
                return nil, fmt.Errorf("reading token response: %w", err)
        }

        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
        }

        var result map[string]any
        if err := json.Unmarshal(body, &result); err != nil {
                return nil, fmt.Errorf("parsing token response: %w", err)
        }

        return result, nil
}

func (h *AuthHandler) fetchUserInfo(accessToken string) (map[string]any, error) {
        req, err := http.NewRequest("GET", googleUserInfoURL, nil)
        if err != nil {
                return nil, fmt.Errorf("creating userinfo request: %w", err)
        }
        req.Header.Set("Authorization", "Bearer "+accessToken)

        resp, err := http.DefaultClient.Do(req)
        if err != nil {
                return nil, fmt.Errorf("userinfo request failed: %w", err)
        }
        defer resp.Body.Close()

        body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        if err != nil {
                return nil, fmt.Errorf("reading userinfo response: %w", err)
        }

        if resp.StatusCode != http.StatusOK {
                return nil, fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, string(body))
        }

        var result map[string]any
        if err := json.Unmarshal(body, &result); err != nil {
                return nil, fmt.Errorf("parsing userinfo response: %w", err)
        }

        return result, nil
}
