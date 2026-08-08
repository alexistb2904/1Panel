package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/gin-gonic/gin"
)

// WebsiteRestrictedBoundaryGuard protects website operations whose apparent
// target is one website but whose parameters can select another filesystem or
// network resource. It deliberately runs after WebsiteRBAC has established a
// scoped identity and before the legacy website service executes.
func WebsiteRestrictedBoundaryGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		if c.GetHeader(headerRBACMode) != rbacModeIDs && c.GetHeader(headerRBACMode) != rbacModeNone {
			c.Next()
			return
		}

		path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/websites")
		if path == "/dir/update" && c.Request.Method == http.MethodPost {
			// Upstream concatenates SiteDir into the Nginx root without a
			// filesystem capability boundary. Traversal/symlink behavior therefore
			// cannot be made tenant-safe by validating a string alone.
			denyWebsiteAccess(c, "Changing a website document root is administrator-only until the root is fd-confined to the project")
			return
		}

		if strings.TrimSuffix(c.Request.URL.Path, "/") == "/api/v2/websites" && c.Request.Method == http.MethodPost {
			body, payload, err := readRBACJSONBody(c)
			if err != nil {
				denyWebsiteAccess(c, "Unable to validate website creation boundary")
				return
			}
			if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
			if err := validateScopedWebsiteBoundary(payload); err != nil {
				denyWebsiteAccess(c, err.Error())
				return
			}
		}
		c.Next()
	}
}

func validateScopedWebsiteBoundary(payload map[string]any) error {
	websiteType := strings.ToLower(strings.TrimSpace(valueString(payload["type"])))
	if websiteType != strings.ToLower(constant.Static) {
		return errors.New("Scoped website creation is limited to standalone static HTTP sites until app, runtime, proxy, stream and subsite dependencies are project-owned")
	}
	if uintValue(payload["parentWebsiteID"]) != 0 {
		return errors.New("Scoped subsite creation is disabled because the parent website is a separate authorization resource")
	}
	if valueString(payload["proxy"]) != "" {
		return errors.New("Scoped website creation may not select an arbitrary reverse-proxy target")
	}
	if raw, ok := payload["streamPorts"]; ok && strings.TrimSpace(valueString(raw)) != "" {
		return errors.New("Scoped website creation may not reserve host stream listener ports")
	}
	if domains, ok := payload["domains"].([]any); ok {
		for _, raw := range domains {
			domain, ok := raw.(map[string]any)
			if !ok { return errors.New("Invalid scoped website domain definition") }
			port := uintValue(domain["port"])
			// The shared OpenResty HTTP listener is the only host listener exposed
			// to project users. Custom listener ports are infrastructure resources.
			if port != 0 && port != 80 {
				return errors.New("Scoped websites may not reserve custom host listener ports")
			}
		}
	}
	return nil
}
