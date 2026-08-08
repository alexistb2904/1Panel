package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// RuntimeRestrictedExecution keeps generic project runtime lifecycle operations
// available while denying specialized package/config/process controls whose
// execution boundary is the host/runtime engine rather than the Core project.
// These can be re-enabled only after their command/file targets are represented
// as explicit project-owned capabilities.
func RuntimeRestrictedExecution() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		mode := c.GetHeader(headerRBACMode)
		if mode != rbacModeIDs && mode != rbacModeNone {
			c.Next()
			return
		}

		path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/runtimes")
		switch {
		case path == "/node/modules" || path == "/node/modules/operate",
			strings.HasPrefix(path, "/php/extensions"),
			path == "/php/config" || path == "/php/update" || path == "/php/file" || path == "/php/fpm/config" || path == "/php/container/update",
			strings.HasPrefix(path, "/supervisor/process"):
			c.JSON(http.StatusOK, gin.H{
				"code":    http.StatusForbidden,
				"message": "This runtime package/config/process operation is administrator-only until its execution target is project-confined",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}
