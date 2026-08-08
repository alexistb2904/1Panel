package rbac

import (
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

// FinalDefaultDenyMiddleware is the last RBAC gate before the Core proxy.
//
// Once Community RBAC has been bootstrapped, an authenticated/legacy request
// without a concrete RBAC identity is never allowed to fall through to the
// historical single-administrator Agent surface. Only the intentionally public
// authentication bootstrap and public file-share endpoints may reach the next
// stage without a user identity.
func FinalDefaultDenyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if !strings.HasPrefix(path, "/api/v2/") {
			c.Next()
			return
		}
		if c.GetBool("API_AUTH") || c.GetBool("LOCAL_REQUEST") {
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			if isAnonymousRBACPath(path) {
				c.Next()
				return
			}
			if CommunityRBACEnabled() {
				deny(c, http.StatusUnauthorized, "RBAC identity is required")
				return
			}
			// Pre-migration/bootstrap compatibility only. Once the RBAC migration
			// has produced an interactive identity this branch is unreachable.
			c.Next()
			return
		}
		admin, err := NewEvaluator(global.DB).CanGlobal(userID, "settings.manage")
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate final RBAC guard")
			return
		}
		if admin {
			c.Next()
			return
		}

		if isExplicitlyScopedAgentFamily(path) || isAllowedRestrictedCorePath(path) {
			c.Next()
			return
		}
		AuditDecision(c, userID, "request.default_deny", "deny", "request", path, 0, 0, "API family has no explicit RBAC policy")
		deny(c, http.StatusForbidden, "This API is administrator-only until an explicit RBAC policy is defined")
	}
}

func isAnonymousRBACPath(path string) bool {
	switch path {
	case "/api/v2/core/auth/captcha",
		"/api/v2/core/auth/passkey/begin",
		"/api/v2/core/auth/passkey/finish",
		"/api/v2/core/auth/mfalogin",
		"/api/v2/core/auth/login",
		"/api/v2/core/auth/logout",
		"/api/v2/core/auth/setting",
		"/api/v2/core/auth/welcome",
		"/api/v2/files/share/info",
		"/api/v2/files/share/check",
		"/api/v2/files/share/download":
		return true
	default:
		return false
	}
}

func isExplicitlyScopedAgentFamily(path string) bool {
	for _, prefix := range []string{
		"/api/v2/websites",
		"/api/v2/databases",
		"/api/v2/runtimes",
		"/api/v2/containers",
		"/api/v2/files",
	} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func isAllowedRestrictedCorePath(path string) bool {
	if strings.HasPrefix(path, "/api/v2/core/access") {
		// Access-control routes carry route-level RequireGlobal checks except for
		// the intentional self-service /me endpoints.
		return true
	}
	switch path {
	case "/api/v2/core/auth/logout",
		"/api/v2/core/auth/mfa",
		"/api/v2/core/auth/mfa/bind",
		"/api/v2/core/auth/mfa/close",
		"/api/v2/core/auth/current",
		"/api/v2/core/auth/current/update",
		"/api/v2/core/auth/expired/reset":
		return true
	default:
		return false
	}
}
