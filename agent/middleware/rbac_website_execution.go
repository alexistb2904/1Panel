package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// WebsiteRestrictedExecution closes confused-deputy and shared-Nginx escape
// paths after WebsiteRBAC has authorized the website itself. Restricted users
// may use structured website-local operations only when those operations cannot
// select an arbitrary host process, network destination or shared Nginx file.
func WebsiteRestrictedExecution() gin.HandlerFunc {
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
		switch path {
		case "/nginx/update",
			"/config/update",
			"/rewrite/update",
			"/redirect/file",
			"/proxies/file",
			"/lbs/file":
			denyWebsiteAccess(c, "Raw or free-form Nginx/OpenResty configuration is administrator-only on a shared host")
			return
		case "/proxies/update", "/proxies/delete", "/proxies/status", "/proxy/config", "/proxy/clear",
			"/lbs/create", "/lbs/del", "/lbs/update":
			// A reverse proxy/load-balancer target is a network capability. Until
			// upstream ports/processes are first-class project-owned resources,
			// allowing arbitrary targets would expose loopback, other projects or
			// internal services through the shared OpenResty process.
			denyWebsiteAccess(c, "Reverse-proxy and load-balancer mutation requires administrator approval until upstream ownership is enforced")
			return
		case "/realip/config":
			denyWebsiteAccess(c, "Trusted real-IP source configuration is administrator-only on a shared reverse proxy")
			return
		case "/crosssite":
			denyWebsiteAccess(c, "Changing cross-site filesystem isolation is administrator-only")
			return
		case "/dir/permission":
			denyWebsiteAccess(c, "Changing website Unix permission modes is administrator-only")
			return
		case "/stream/update":
			denyWebsiteAccess(c, "Stream listener reconfiguration is administrator-only on a shared host")
			return
		case "/exec/composer":
			// Composer plugins/scripts execute commands as the Agent's host-side
			// website user. The legacy path containment check is pathname-based and
			// does not provide an OS sandbox. Keep this surface administrator-only
			// until execution is moved into a project-confined runtime.
			denyWebsiteAccess(c, "Host-side Composer command execution is administrator-only for scoped users")
			return
		case "/php/version":
			// Selecting a runtime by Agent-local ID can attach a website to a
			// runtime owned by another Core project. Require an explicit scoped
			// runtime-link capability before exposing this operation.
			denyWebsiteAccess(c, "Changing website runtime attachment requires administrator approval")
			return
		}

		if c.Request.Method == http.MethodPost && strings.TrimSuffix(c.Request.URL.Path, "/") == "/api/v2/websites" {
			body, payload, err := readRBACJSONBody(c)
			if err != nil { denyWebsiteAccess(c, "Unable to validate website creation side effects"); return }
			if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
			if err := validateRestrictedWebsiteCreation(payload); err != nil { denyWebsiteAccess(c, err.Error()); return }
		}

		if path == "/del" && c.Request.Method == http.MethodPost {
			body, payload, err := readRBACJSONBody(c)
			if err != nil { denyWebsiteAccess(c, "Unable to validate website deletion side effects"); return }
			if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
			if boolValue(payload["deleteDB"]) || boolValue(payload["deleteApp"]) {
				denyWebsiteAccess(c, "Deleting a website may not implicitly delete its database or application; delete those resources through their own scoped APIs")
				return
			}
			if boolValue(payload["deleteBackup"]) {
				denyWebsiteAccess(c, "Deleting backups requires the dedicated backup permission and cannot be implied by website.delete")
				return
			}
			if boolValue(payload["forceDelete"]) {
				denyWebsiteAccess(c, "Forced website deletion is administrator-only")
				return
			}
		}
		c.Next()
	}
}

func validateRestrictedWebsiteCreation(payload map[string]any) error {
	if boolValue(payload["createDb"]) {
		return errors.New("Implicit database creation is disabled for scoped websites; create the database through the scoped Database API first")
	}
	if valueString(payload["ftpUser"]) != "" || valueString(payload["ftpPassword"]) != "" {
		return errors.New("Implicit FTP-account creation is disabled for scoped websites")
	}
	if boolValue(payload["enableSSL"]) || uintValue(payload["websiteSSLID"]) != 0 {
		return errors.New("Implicit TLS certificate assignment is disabled for scoped website creation; configure TLS through website.ssl.manage after creation")
	}
	if valueString(payload["appType"]) != "" || uintValue(payload["appID"]) != 0 || uintValue(payload["appInstallID"]) != 0 {
		return errors.New("Implicit application installation/attachment is disabled for scoped website creation")
	}
	if uintValue(payload["runtimeID"]) != 0 {
		return errors.New("Attaching an existing runtime during website creation requires administrator approval; create the site first and use an explicitly scoped runtime workflow")
	}
	return nil
}
