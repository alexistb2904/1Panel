package rbac

import (
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

var mfaEnrollmentAllowedPaths = map[string]struct{}{
	"/api/v2/core/auth/current":  {},
	"/api/v2/core/auth/mfa":      {},
	"/api/v2/core/auth/mfa/bind": {},
	"/api/v2/core/auth/logout":   {},
}

// MandatoryMFAGate allows a newly provisioned account to establish a session
// so it can enroll MFA, but blocks every other authenticated API until the
// required second factor has actually been configured.
func MandatoryMFAGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/v2/") {
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			c.Next()
			return
		}
		var user model.AccessUser
		if err := global.DB.Select("id", "require_mfa", "mfa_enabled").First(&user, userID).Error; err != nil {
			deny(c, http.StatusUnauthorized, "Unable to validate MFA policy")
			return
		}
		if !user.RequireMFA || user.MFAEnabled {
			c.Next()
			return
		}
		if _, allowed := mfaEnrollmentAllowedPaths[c.Request.URL.Path]; allowed {
			c.Next()
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"code":    http.StatusPreconditionRequired,
			"message": "MFA enrollment is required before accessing 1Panel resources",
			"data": gin.H{
				"requireMFAEnrollment": true,
			},
		})
		c.Abort()
	}
}
