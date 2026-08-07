package rbac

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

const (
	HeaderRBACMode         = "X-Panel-RBAC-Mode"
	HeaderRBACPermission   = "X-Panel-RBAC-Permission"
	HeaderRBACResourceType = "X-Panel-RBAC-Resource-Type"
	HeaderRBACResourceIDs  = "X-Panel-RBAC-Resource-IDs"
	HeaderRBACUserID       = "X-Panel-RBAC-User-ID"

	RBACModeAll  = "all"
	RBACModeIDs  = "ids"
	RBACModeNone = "none"
)

func AgentResourceAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		clearAgentRBACHeaders(c)
		if !strings.HasPrefix(c.Request.URL.Path, "/api/v2/websites") {
			c.Next()
			return
		}
		if c.GetBool("API_AUTH") || c.GetBool("LOCAL_REQUEST") {
			setAgentRBACHeaders(c, 0, "platform.internal", "website", ResourceFilter{All: true})
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required for website access")
			return
		}
		evaluator := NewEvaluator(global.DB)
		isAdministrator, err := evaluator.CanGlobal(userID, "settings.manage")
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate website access")
			return
		}
		if isAdministrator {
			setAgentRBACHeaders(c, userID, "administrator", "website", ResourceFilter{All: true})
			c.Next()
			return
		}
		nodeID, _, err := ResolveRequestNodeID(c)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}

		if c.Request.Method == http.MethodPost && strings.TrimSuffix(c.Request.URL.Path, "/") == "/api/v2/websites" {
			body, payload, err := readJSONBody(c)
			if err != nil {
				deny(c, http.StatusBadRequest, "Unable to parse website creation target")
				return
			}
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
			projectID := projectIDFromPayload(payload)
			alias := strings.TrimSpace(stringValue(payload["alias"]))
			resourceID := "website:" + alias
			if projectID == 0 || alias == "" {
				deny(c, http.StatusPreconditionFailed, "projectID and website alias are required")
				return
			}
			allowed, err := evaluator.Can(userID, "website.create", ResourceContext{NodeID: nodeID, ProjectID: projectID, Type: "project", ID: strconv.FormatUint(uint64(projectID), 10)})
			if err != nil || !allowed {
				deny(c, http.StatusPreconditionFailed, "Website creation is not allowed in this project on the selected node")
				return
			}
			var project model.AccessProject
			if err := global.DB.First(&project, projectID).Error; err != nil || project.Status != "active" {
				deny(c, http.StatusPreconditionFailed, "Project is not active")
				return
			}
			if _, err := projectResourceOwnedBy(projectID, nodeID, "website", resourceID); err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			setAgentRBACHeaders(c, userID, "website.create", "website", ResourceFilter{IDs: []string{resourceID}})
			if err := setProjectTransportHeaders(c, project, nodeID); err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			ContinueCreationWithOwnership(c, projectID, nodeID, "website", resourceID)
			return
		}

		permission, ok := websitePermissionForRequest(c.Request.Method, c.Request.URL.Path)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "This website operation is restricted to administrators until an explicit RBAC policy is defined")
			return
		}
		filter, err := evaluator.AccessibleResourceIDs(userID, permission, "website", nodeID)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to resolve website scope")
			return
		}
		setAgentRBACHeaders(c, userID, permission, "website", filter)
		c.Next()
	}
}

func clearAgentRBACHeaders(c *gin.Context) {
	for _, key := range []string{HeaderRBACMode, HeaderRBACPermission, HeaderRBACResourceType, HeaderRBACResourceIDs, HeaderRBACUserID, HeaderRBACAllowedRoots, HeaderRBACProjectID, HeaderRBACProjectRoot, HeaderRBACRestricted} {
		c.Request.Header.Del(key)
	}
}

func setAgentRBACHeaders(c *gin.Context, userID uint, permission, resourceType string, filter ResourceFilter) {
	c.Request.Header.Set(HeaderRBACPermission, permission)
	c.Request.Header.Set(HeaderRBACResourceType, resourceType)
	if userID != 0 {
		c.Request.Header.Set(HeaderRBACUserID, strconv.FormatUint(uint64(userID), 10))
	}
	if filter.All {
		c.Request.Header.Set(HeaderRBACMode, RBACModeAll)
		c.Request.Header.Del(HeaderRBACResourceIDs)
		return
	}
	if len(filter.IDs) == 0 {
		c.Request.Header.Set(HeaderRBACMode, RBACModeNone)
		c.Request.Header.Del(HeaderRBACResourceIDs)
		return
	}
	c.Request.Header.Set(HeaderRBACMode, RBACModeIDs)
	c.Request.Header.Set(HeaderRBACResourceIDs, strings.Join(filter.IDs, ","))
}

func websitePermissionForRequest(method, fullPath string) (string, bool) {
	path := strings.TrimPrefix(fullPath, "/api/v2/websites")
	if path == "" || path == "/" { return "", false }
	switch path {
	case "/search", "/options":
		if method == http.MethodPost { return "website.view", true }
	case "/list":
		if method == http.MethodGet { return "website.view", true }
	case "/operate": return "website.runtime.restart", method == http.MethodPost
	case "/update": return "website.update", method == http.MethodPost
	case "/del": return "website.delete", method == http.MethodPost
	case "/log/search": return "website.logs.view", method == http.MethodPost
	case "/log/operate": return "website.update", method == http.MethodPost
	case "/group/change", "/batch/group": return "website.update", method == http.MethodPost
	case "/batch/operate": return "website.runtime.restart", method == http.MethodPost
	case "/batch/ssl": return "website.ssl.manage", method == http.MethodPost
	case "/domains":
		if method == http.MethodPost { return "website.domain.manage", true }
	case "/domains/del", "/domains/update": return "website.domain.manage", method == http.MethodPost
	case "/config": return "website.config.view", method == http.MethodPost
	case "/config/update", "/nginx/update", "/rewrite/update", "/dir/update", "/dir/permission",
		"/proxies/update", "/proxies/delete", "/proxies/status", "/proxies/file", "/proxy/config", "/proxy/clear",
		"/auths/update", "/auths/path/update", "/cors/update", "/leech/update", "/redirect/update", "/redirect/file",
		"/lbs/create", "/lbs/del", "/lbs/update", "/lbs/file", "/realip/config", "/crosssite", "/stream/update":
		return "website.config.edit", method == http.MethodPost
	case "/rewrite", "/dir", "/proxies", "/auths", "/auths/path", "/leech", "/redirect": return "website.config.view", method == http.MethodPost
	case "/php/version": return "website.runtime.manage", method == http.MethodPost
	case "/exec/composer": return "website.shell", method == http.MethodPost
	}
	segments := splitPath(path)
	if len(segments) == 0 { return "", false }
	if segments[0] == "domains" && len(segments) == 2 && method == http.MethodGet { return "website.domain.view", true }
	if segments[0] == "cors" && len(segments) == 2 && method == http.MethodGet { return "website.config.view", true }
	if segments[0] == "realip" && len(segments) == 3 && segments[1] == "config" && method == http.MethodGet { return "website.config.view", true }
	if segments[0] == "proxy" && len(segments) == 3 && segments[1] == "config" && method == http.MethodGet { return "website.config.view", true }
	if segments[0] == "resource" && len(segments) == 2 && method == http.MethodGet { return "website.view", true }
	if _, err := strconv.ParseUint(segments[0], 10, 64); err == nil {
		if len(segments) == 1 && method == http.MethodGet { return "website.view", true }
		if len(segments) == 2 && segments[1] == "https" {
			if method == http.MethodGet { return "website.ssl.view", true }
			if method == http.MethodPost { return "website.ssl.manage", true }
		}
		if len(segments) >= 2 && segments[1] == "config" && method == http.MethodGet { return "website.config.view", true }
		if len(segments) == 2 && segments[1] == "lbs" && method == http.MethodGet { return "website.config.view", true }
	}
	return "", false
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" { return nil }
	return strings.Split(trimmed, "/")
}
