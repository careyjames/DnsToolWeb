package handlers

import (
	"dnstool/go-server/internal/config"

	"github.com/gin-gonic/gin"
)

func mergeAuthData(c *gin.Context, cfg *config.Config, data gin.H) gin.H {
	if auth, exists := c.Get("authenticated"); exists && auth == true {
		email, _ := c.Get("user_email")
		name, _ := c.Get("user_name")
		role, _ := c.Get("user_role")
		data["Authenticated"] = true
		data["UserEmail"] = email
		data["UserName"] = name
		data["UserRole"] = role
	}
	if cfg.GoogleClientID != "" {
		data["GoogleAuthEnabled"] = true
	}
	return data
}
