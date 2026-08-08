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

// DockerScopedStreamLogBridge covers the one legacy GET streaming route that
// predates the Agent JSON target resolver. Core has already selected the
// docker.container.logs capability, but Agent still independently resolves the
// requested Docker target to a canonical project-owned container before using
// the internal marker to skip only the legacy resolver for this exact route.
func DockerScopedStreamLogBridge() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet || c.Request.URL.Path != "/api/v2/containers/search/log" {
			c.Next()
			return
		}
		if c.GetHeader(headerDockerRBACMode) != dockerRBACModeIDs {
			c.Next()
			return
		}
		if c.GetHeader("X-Panel-RBAC-Permission") != "docker.container.logs" {
			denyDocker(c, "Invalid Docker log capability")
			return
		}
		target := strings.TrimSpace(c.Query("container"))
		if target == "" { target = strings.TrimSpace(c.Query("name")) }
		if target == "" {
			denyDocker(c, "Docker log target is required")
			return
		}
		allowed := parseRBACStringIDs(c.GetHeader(headerDockerRBACResourceIDs))
		if !authorizedContainerTarget(target, allowed) {
			denyDocker(c, "Container log access denied")
			return
		}
		c.Request.Header.Set(headerDockerInternalRequest, "1")
		c.Next()
		c.Request.Header.Del(headerDockerInternalRequest)
	}
}
