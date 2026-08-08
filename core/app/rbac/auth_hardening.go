package rbac

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var communityUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{2,127}$`)
var loginLanguageMu sync.Mutex

// CommunityRBACEnabled is a schema-level, monotonic switch. The RBAC migration
// runs before the HTTP server starts and bootstraps the legacy administrator.
// Once the rbac_users table exists, Settings-based credentials must never become
// a fallback again, even if all RBAC users are later deleted or the table is
// temporarily unreadable. This prevents an empty/corrupt RBAC database from
// resurrecting stale administrator credentials.
func CommunityRBACEnabled() bool {
	return global.DB != nil && global.DB.Migrator().HasTable(&model.AccessUser{})
}

// PreserveGlobalLanguageOnLogin prevents an unauthenticated login attempt from
// permanently mutating the installation-wide Language setting. The legacy
// handler changes Language before validating credentials; multi-user Community
// treats the request language as transient input and restores the global value
// after the login handler completes. Login attempts are serialized around this
// legacy mutation so concurrent requests cannot interleave snapshot/restore and
// accidentally persist another request's transient language.
func PreserveGlobalLanguageOnLogin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !CommunityRBACEnabled() {
			c.Next()
			return
		}
		loginLanguageMu.Lock()
		defer loginLanguageMu.Unlock()
		var setting model.Setting
		if err := global.DB.Where("key = ?", "Language").First(&setting).Error; err != nil {
			deny(c, http.StatusInternalServerError, "Unable to preserve login language setting")
			return
		}
		original := setting.Value
		c.Next()
		if err := global.DB.Model(&model.Setting{}).Where("key = ?", "Language").Update("value", original).Error; err != nil {
			global.LOG.Errorf("restore global Language after login attempt failed: %v", err)
		}
	}
}

// RejectLegacyLoginAfterRBAC prevents the historical Settings UserName /
// Password fallback from becoming a second, stale administrator credential
// after the migration has copied the administrator into rbac_users.
func RejectLegacyLoginAfterRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !CommunityRBACEnabled() {
			c.Next()
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse login request")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		var payload struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(body, &payload); err != nil || strings.TrimSpace(payload.Name) == "" {
			c.Next()
			return
		}
		var user model.AccessUser
		err = global.DB.Where("username = ?", strings.TrimSpace(payload.Name)).First(&user).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				deny(c, http.StatusUnauthorized, "Invalid credentials")
				return
			}
			deny(c, http.StatusInternalServerError, "Unable to resolve authentication identity")
			return
		}
		if user.AuthSource == "service_account" || user.Status != model.AccessUserStatusActive {
			deny(c, http.StatusUnauthorized, "Invalid credentials")
			return
		}
		c.Next()
	}
}

// DisableLegacyPasskeyLoginAfterRBAC closes the legacy WebAuthn path after the
// multi-user migration. Community passkeys were historically tied to the
// single Settings administrator and are not per-rbac-user credentials. Keeping
// that path enabled would preserve a stale administrator authentication source.
func DisableLegacyPasskeyLoginAfterRBAC() gin.HandlerFunc {
	return func(c *gin.Context) {
		if CommunityRBACEnabled() {
			deny(c, http.StatusForbidden, "Legacy passkey login is disabled after enabling Community multi-user authentication")
			return
		}
		c.Next()
	}
}

// RequireInteractiveUser is used by account self-service routes. A scoped
// service account is an API principal, never an interactive user profile, and
// a legacy super-admin session without an RBAC identity is not accepted once
// Community RBAC is enabled.
func RequireInteractiveUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetBool("SCOPED_API_AUTH") {
			deny(c, http.StatusForbidden, "Service accounts cannot use interactive account endpoints")
			return
		}
		if subject, ok := c.Get(GinContextRBACSubjectTypeKey); ok {
			if value, ok := subject.(string); ok && value == "service_account" {
				deny(c, http.StatusForbidden, "Service accounts cannot use interactive account endpoints")
				return
			}
		}
		if _, ok := CurrentUserID(c); !ok && CommunityRBACEnabled() {
			deny(c, http.StatusUnauthorized, "An interactive RBAC identity is required")
			return
		}
		c.Next()
	}
}

// ValidateCurrentUserUpdate applies the same minimum account invariants to the
// self-service endpoint as administrator-created users. Client-side validation
// is not an authorization or password-policy boundary.
func ValidateCurrentUserUpdate() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse account update")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		var payload struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse account update")
			return
		}
		name := strings.TrimSpace(payload.Name)
		if !communityUsernamePattern.MatchString(name) {
			deny(c, http.StatusBadRequest, "Username contains unsupported characters")
			return
		}
		if payload.Password != "" {
			decoded, err := base64.StdEncoding.DecodeString(payload.Password)
			if err != nil {
				deny(c, http.StatusBadRequest, "Invalid password encoding")
				return
			}
			if len(decoded) < 12 || len(decoded) > 256 {
				deny(c, http.StatusBadRequest, "Password must contain between 12 and 256 bytes")
				return
			}
		}
		c.Next()
	}
}
