package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	initauth "github.com/1Panel-dev/1Panel/core/init/auth"
	"github.com/gin-gonic/gin"
)

// RequireCommunityMFASessionAfterRBAC prevents a stale legacy single-admin MFA
// session from completing authentication after the multi-user migration. New
// Community MFA sessions are explicitly tagged with AuthSource="community".
func RequireCommunityMFASessionAfterRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !CommunityRBACEnabled() {
			c.Next()
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse MFA login request")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		var payload struct {
			SessionID string `json:"sessionID"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || strings.TrimSpace(payload.SessionID) == "" {
			deny(c, http.StatusUnauthorized, "Invalid MFA session")
			return
		}
		session, ok := initauth.GetMFASessionStore().Get(strings.TrimSpace(payload.SessionID))
		if !ok || session.AuthSource != "community" {
			deny(c, http.StatusUnauthorized, "Legacy MFA sessions are disabled after enabling Community multi-user authentication")
			return
		}
		c.Next()
	}
}
