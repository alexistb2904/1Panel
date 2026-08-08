package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// DockerScopedHostPathGuard closes the remaining check/use race between
// pathname validation in Agent and the Docker daemon consuming a bind source.
// A hostile workload inside the same project can rename/symlink a validated
// path after EvalSymlinks and before dockerd opens it. There is no fd-relative
// handoff in the Docker API, so the strong boundary is to disallow host bind
// mounts for scoped principals. Named Compose volumes and tmpfs remain usable.
func DockerScopedHostPathGuard() gin.HandlerFunc {
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
		switch path {
		case "", "/update":
			if c.Request.Method != http.MethodPost {
				c.Next()
				return
			}
			var req dto.ContainerOperate
			if !bindReusableJSON(c, &req) {
				return
			}
			for _, volume := range req.Volumes {
				if strings.EqualFold(strings.TrimSpace(volume.Type), "bind") {
					denyDocker(c, "Host bind mounts are administrator-only until Docker supports an fd-confined project-root handoff")
					return
				}
			}
		case "/compose", "/compose/test":
			if c.Request.Method != http.MethodPost {
				c.Next()
				return
			}
			var req dto.ComposeCreate
			if !bindReusableJSON(c, &req) {
				return
			}
			if err := rejectScopedComposeHostPaths(req.File); err != nil {
				denyDocker(c, err.Error())
				return
			}
		case "/compose/update":
			var req dto.ComposeUpdate
			if !bindReusableJSON(c, &req) {
				return
			}
			if err := rejectScopedComposeHostPaths(req.Content); err != nil {
				denyDocker(c, err.Error())
				return
			}
		}
		c.Next()
	}
}

func rejectScopedComposeHostPaths(content string) error {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	var document map[string]any
	if err := yaml.Unmarshal([]byte(content), &document); err != nil {
		return err
	}
	declared := map[string]struct{}{}
	if raw, ok := document["volumes"].(map[string]any); ok {
		for name := range raw {
			declared[name] = struct{}{}
		}
	}
	services, ok := document["services"].(map[string]any)
	if !ok {
		return nil
	}
	for serviceName, raw := range services {
		service, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		items, ok := service["volumes"].([]any)
		if !ok {
			continue
		}
		for _, rawVolume := range items {
			switch volume := rawVolume.(type) {
			case string:
				source := composeShortVolumeSource(volume)
				if source == "" {
					continue // anonymous volume
				}
				if _, named := declared[source]; named {
					continue
				}
				return errors.New("service " + serviceName + ": host bind mounts are administrator-only for scoped Compose")
			case map[string]any:
				typeName := strings.ToLower(valueString(volume["type"]))
				source := valueString(volume["source"])
				if typeName == "bind" {
					return errors.New("service " + serviceName + ": host bind mounts are administrator-only for scoped Compose")
				}
				if (typeName == "" || typeName == "volume") && source != "" {
					if _, named := declared[source]; !named {
						return errors.New("service " + serviceName + ": undeclared volume source is not a project-owned named volume")
					}
				}
			}
		}
	}
	return nil
}
