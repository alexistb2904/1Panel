package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// NormalizeDockerRBACTransport bridges the structured b64 JSON resource list
// emitted by hardened Core builds to the legacy Docker middleware's internal
// comma-separated helper. Docker and Compose canonical names containing commas
// are rejected rather than encoded ambiguously. This middleware can be removed
// once all supported rolling-upgrade versions parse the structured transport
// natively.
func NormalizeDockerRBACTransport() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerDockerRBACMode) != dockerRBACModeIDs {
			c.Next()
			return
		}
		raw := strings.TrimSpace(c.GetHeader(headerDockerRBACResourceIDs))
		if raw == "" || !strings.HasPrefix(raw, "b64:") {
			c.Next()
			return
		}
		ids := parseRBACStringIDs(raw)
		if len(ids) == 0 {
			c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": "Invalid structured Docker RBAC resource context"})
			c.Abort()
			return
		}
		for _, id := range ids {
			if strings.Contains(id, ",") || strings.ContainsAny(id, "\r\n") {
				c.JSON(http.StatusOK, gin.H{"code": http.StatusForbidden, "message": "Unsafe Docker resource identity in RBAC context"})
				c.Abort()
				return
			}
		}
		c.Request.Header.Set(headerDockerRBACResourceIDs, strings.Join(ids, ","))
		c.Next()
	}
}
