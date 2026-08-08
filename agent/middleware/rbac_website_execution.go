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
// may use structured, website-local operations, but may not use a website
// handler as a deputy to create/delete unrelated DB/App/FTP resources or write
// arbitrary shared OpenResty/Nginx configuration.
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
		case "/crosssite":
			denyWebsiteAccess(c, "Changing cross-site filesystem isolation is administrator-only")
			return
		case "/dir/permission":
			denyWebsiteAccess(c, "Changing website Unix permission modes is administrator-only")
			return
		case "/stream/update":
			denyWebsiteAccess(c, "Stream listener reconfiguration is administrator-only on a shared host")
			return
		}

		if c.Request.Method == http.MethodPost && strings.TrimSuffix(c.Request.URL.Path, "/") == "/api/v2/websites" {
			body, payload, err := readRBACJSONBody(c)
			if err != nil { denyWebsiteAccess(c, "Unable to validate website creation side effects"); return }
			if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
			if err := validateRestrictedWebsiteCreation(payload); err != nil {
				denyWebsiteAccess(c, err.Error())
				return
			}
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
	// A runtime ID is an Agent-local numeric identity and cannot be proven to
	// belong to the Core project from this request alone. Until runtime->website
	// ownership is transported as a verified capability, fail closed instead of
	// allowing a website permission to attach another project's runtime.
	if uintValue(payload["runtimeID"]) != 0 {
		return errors.New("Attaching an existing runtime during website creation requires administrator approval; create the site first and use an explicitly scoped runtime workflow")
	}
	return nil
}
