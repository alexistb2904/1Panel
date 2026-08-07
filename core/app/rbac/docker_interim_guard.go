package rbac

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// DockerInterimGuard keeps the branch fail-closed while the Agent-side Docker
// technical policy is being introduced. Non-admin users may operate/view only
// explicitly assigned resources; create/reconfigure paths stay blocked until
// the Agent can reject privilege-escalating Docker definitions.
func DockerInterimGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/v2/containers") {
			c.Next()
			return
		}
		if c.GetHeader(HeaderRBACMode) == RBACModeAll {
			c.Next()
			return
		}
		if c.GetHeader(HeaderRBACRestricted) != "1" {
			deny(c, http.StatusPreconditionFailed, "Restricted Docker policy context is missing")
			return
		}

		ctx, body, err := classifyDockerRequest(c)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to validate Docker target")
			return
		}
		if body != nil {
			// classifyDockerRequest already restores the request body; retaining
			// the variable makes the fail-closed intent explicit.
			_ = body
		}

		if ctx.Creating || dockerRequestReconfiguresRuntime(c.Request.URL.Path) {
			deny(c, http.StatusPreconditionFailed, "Restricted Docker create/update is not enabled until the Agent anti-escalation policy is active")
			return
		}
		if len(ctx.Targets) == 0 {
			// Search/list/stats require Agent-side filtering. Returning the global
			// collection would leak resources from other projects.
			deny(c, http.StatusPreconditionFailed, "Scoped Docker collections are not enabled yet")
			return
		}

		allowed := make(map[string]struct{})
		if c.GetHeader(HeaderRBACMode) == RBACModeIDs {
			for _, id := range strings.Split(c.GetHeader(HeaderRBACResourceIDs), ",") {
				id = strings.TrimSpace(id)
				if id != "" {
					allowed[id] = struct{}{}
				}
		}
		}
		for _, target := range ctx.Targets {
			if _, ok := allowed[strings.TrimSpace(target)]; !ok {
				deny(c, http.StatusPreconditionFailed, "Docker resource is outside the assigned project scope")
				return
			}
		}
		c.Next()
	}
}

func dockerRequestReconfiguresRuntime(path string) bool {
	relative := strings.TrimPrefix(path, "/api/v2/containers")
	switch relative {
	case "/update", "/upgrade", "/rename", "/commit", "/compose/update", "/compose/test":
		return true
	default:
		return false
	}
}
