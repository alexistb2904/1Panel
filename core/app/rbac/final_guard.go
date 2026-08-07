package rbac

import (
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

// FinalDefaultDenyMiddleware is the last RBAC gate before the Core proxy.
//
// 1Panel Community historically assumes a single trusted administrator, so
// many legacy Agent routes only require an authenticated session. Once multiple
// users exist, that assumption is unsafe. Restricted RBAC identities may only
// reach Agent API families that have an explicit scoped middleware, plus a
// small set of Core self-service/access-control routes that are protected by
// their route-level guards.
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
			// Anonymous login/public routes and legacy bootstrap are handled by the
			// existing authentication stack. This guard only constrains an RBAC
			// identity that has already been established.
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
