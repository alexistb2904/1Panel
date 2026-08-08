package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// DockerRestrictedLifecycleGate closes scoped Docker/Compose operations whose
// upstream HTTP acknowledgement does not prove the corresponding resource
// lifecycle has completed, as well as broad read endpoints that return raw
// secrets. It runs after DockerRBAC has established a restricted project scope
// and before the legacy handler is allowed to execute.
func DockerRestrictedLifecycleGate() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerDockerInternalRequest) == "1" || c.GetHeader(headerDockerRBACMode) == dockerRBACModeAll {
			c.Next()
			return
		}
		if c.GetHeader(headerDockerRBACMode) != dockerRBACModeIDs || c.GetHeader(headerDockerRBACRestricted) != "1" {
			c.Next()
			return
		}

		path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
		switch {
		case path == "/compose" && c.Request.Method == http.MethodPost:
			// ContainerService.CreateCompose schedules docker compose up in a
			// goroutine and immediately returns nil. Core therefore cannot safely
			// promote the pending ownership reservation from this HTTP response.
			denyDocker(c, "Compose creation is administrator-only until asynchronous task completion is bound to RBAC ownership activation")
			return
		case path == "/compose/env" && c.Request.Method == http.MethodPost:
			// LoadComposeEnv reads the raw .env file. There is no field-level
			// distinction between ordinary configuration and credentials/tokens,
			// so a generic compose view capability must never expose this endpoint.
			denyDocker(c, "Raw Compose environment values are secret-bearing and administrator-only")
			return
		}
		c.Next()
	}
}
