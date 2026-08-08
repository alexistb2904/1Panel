package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	HeaderRBACProjectID   = "X-Panel-RBAC-Project-ID"
	HeaderRBACProjectRoot = "X-Panel-RBAC-Project-Root"
	HeaderRBACRestricted  = "X-Panel-RBAC-Restricted"
)

type dockerRequestContext struct {
	Permission   string
	ResourceType string
	Targets      []string
	ProjectID    uint
	Creating     bool
}

// DockerAuthorizationMiddleware keeps Docker decisions in Core while Agent
// enforces both target scope and a technical anti-escalation policy. Unknown
// Docker endpoints stay administrator-only until explicitly classified.
func DockerAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/v2/containers") {
			c.Next()
			return
		}
		clearDockerRBACHeaders(c)

		if c.GetBool("API_AUTH") || c.GetBool("LOCAL_REQUEST") {
			setAgentRBACHeaders(c, 0, "platform.internal", "docker", ResourceFilter{All: true})
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required for Docker access")
			return
		}
		evaluator := NewEvaluator(global.DB)
		admin, err := evaluator.Can(userID, "settings.manage", ResourceContext{})
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate Docker access")
			return
		}
		if admin {
			setAgentRBACHeaders(c, userID, "administrator", "docker", ResourceFilter{All: true})
			c.Next()
			return
		}

		ctx, body, err := classifyDockerRequest(c)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse Docker authorization target")
			return
		}
		if ctx.Permission == "" {
			deny(c, http.StatusPreconditionFailed, "This Docker operation is restricted to administrators")
			return
		}
		if body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}

		if ctx.Creating {
			project, err := authorizeDockerProjectCreation(evaluator, userID, ctx)
			if err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			setAgentRBACHeaders(c, userID, ctx.Permission, ctx.ResourceType, ResourceFilter{IDs: ctx.Targets})
			c.Request.Header.Set(HeaderRBACRestricted, "1")
			c.Request.Header.Set(HeaderRBACProjectID, strconv.FormatUint(uint64(project.ID), 10))
			c.Request.Header.Set(HeaderRBACProjectRoot, project.RootPath)
			// Pre-registering the requested deterministic Docker/Compose name is
			// fail-safe: a failed create only leaves a stale, non-existent binding;
			// it never grants access to another existing project resource because
			// uniqueness is checked first.
			if err := reserveProjectDockerResource(project.ID, ctx.ResourceType, ctx.Targets[0]); err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			c.Next()
			return
		}

		filter, err := evaluator.AccessibleResourceIDs(userID, ctx.Permission, ctx.ResourceType, 0)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to resolve Docker resource scope")
			return
		}
		setAgentRBACHeaders(c, userID, ctx.Permission, ctx.ResourceType, filter)
		c.Request.Header.Set(HeaderRBACRestricted, "1")
		c.Next()
	}
}

func clearDockerRBACHeaders(c *gin.Context) {
	clearAgentRBACHeaders(c)
	for _, key := range []string{HeaderRBACProjectID, HeaderRBACProjectRoot, HeaderRBACRestricted} {
		c.Request.Header.Del(key)
	}
}

func classifyDockerRequest(c *gin.Context) (dockerRequestContext, []byte, error) {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
	method := c.Request.Method
	body, payload, err := readJSONBody(c)
	if err != nil {
		return dockerRequestContext{}, body, err
	}
	value := func(key string) string { return stringValue(payload[key]) }
	values := func(key string) []string { return stringSlice(payload[key]) }
	projectID := uintValueJSON(payload["projectID"])
	if projectID == 0 {
		projectID = uintValueJSON(payload["projectId"])
	}

	switch path {
	case "/search", "/list", "/stats":
		return dockerRequestContext{Permission: "docker.container.view", ResourceType: "container"}, body, nil
	case "/status":
		// Global Docker status includes images/networks/volumes/repositories and
		// is intentionally not exposed through container.view.
		return dockerRequestContext{}, body, nil
	case "/info", "/users":
		return dockerRequestContext{Permission: "docker.container.view", ResourceType: "container", Targets: []string{value("name")}}, body, nil
	case "/operate":
		permission := "docker.container.restart"
		switch value("operation") {
		case "start", "up", "unpause":
			permission = "docker.container.start"
		case "stop", "pause", "kill":
			permission = "docker.container.stop"
		case "restart":
			permission = "docker.container.restart"
		case "remove":
			permission = "docker.container.delete"
		default:
			return dockerRequestContext{}, body, nil
		}
		return dockerRequestContext{Permission: permission, ResourceType: "container", Targets: values("names")}, body, nil
	case "/update", "/upgrade", "/rename", "/commit":
		targets := []string{value("name")}
		if path == "/upgrade" {
			targets = values("names")
		}
		if path == "/commit" {
			targets = []string{value("containerID")}
		}
		return dockerRequestContext{Permission: "docker.container.edit", ResourceType: "container", Targets: targets}, body, nil
	case "":
		if method == http.MethodPost {
			name := value("name")
			return dockerRequestContext{Permission: "docker.container.create", ResourceType: "container", Targets: []string{name}, ProjectID: projectID, Creating: true}, body, nil
		}
	case "/files/search", "/files/content", "/files/size", "/files/download":
		return dockerRequestContext{Permission: "docker.container.exec", ResourceType: "container", Targets: []string{value("containerID")}}, body, nil
	case "/files/del":
		return dockerRequestContext{Permission: "docker.container.exec", ResourceType: "container", Targets: []string{value("containerID")}}, body, nil
	case "/logs", "/log":
		return dockerRequestContext{Permission: "docker.container.logs", ResourceType: "container", Targets: []string{value("container")}}, body, nil
	case "/inspect":
		typeName := value("type")
		id := value("id")
		if typeName == "container" {
			return dockerRequestContext{Permission: "docker.container.view", ResourceType: "container", Targets: []string{id}}, body, nil
		}
		if typeName == "compose" {
			return dockerRequestContext{Permission: "docker.compose.view", ResourceType: "compose", Targets: []string{id}}, body, nil
		}
		return dockerRequestContext{}, body, nil
	case "/compose/search":
		return dockerRequestContext{Permission: "docker.compose.view", ResourceType: "compose"}, body, nil
	case "/compose/env":
		return dockerRequestContext{Permission: "docker.compose.env.view", ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose/logs":
		return dockerRequestContext{Permission: "docker.compose.logs", ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose/operate":
		permission := "docker.compose.deploy"
		switch value("operation") {
		case "stop":
			permission = "docker.compose.stop"
		case "delete", "down":
			permission = "docker.compose.delete"
		case "up", "start", "restart", "rebuild":
			permission = "docker.compose.deploy"
		default:
			return dockerRequestContext{}, body, nil
		}
		return dockerRequestContext{Permission: permission, ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose/update", "/compose/pin":
		return dockerRequestContext{Permission: "docker.compose.edit", ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose":
		if method == http.MethodPost {
			return dockerRequestContext{Permission: "docker.compose.create", ResourceType: "compose", Targets: []string{value("name")}, ProjectID: projectID, Creating: true}, body, nil
		}
	case "/compose/test":
		return dockerRequestContext{Permission: "docker.compose.create", ResourceType: "compose", ProjectID: projectID, Creating: true, Targets: []string{"__compose_test__"}}, body, nil
	}
	return dockerRequestContext{}, body, nil
}

func authorizeDockerProjectCreation(evaluator *Evaluator, userID uint, ctx dockerRequestContext) (model.AccessProject, error) {
	if ctx.ProjectID == 0 || len(ctx.Targets) == 0 || strings.TrimSpace(ctx.Targets[0]) == "" {
		return model.AccessProject{}, errors.New("Docker creation requires a projectID and a stable resource name")
	}
	allowed, err := evaluator.Can(userID, ctx.Permission, ResourceContext{ProjectID: ctx.ProjectID, Type: "project", ID: strconv.FormatUint(uint64(ctx.ProjectID), 10)})
	if err != nil || !allowed {
		return model.AccessProject{}, errors.New("Docker creation is not allowed for this project")
	}
	var project model.AccessProject
	if err := global.DB.First(&project, ctx.ProjectID).Error; err != nil {
		return model.AccessProject{}, errors.New("project does not exist")
	}
	if project.Status != "active" {
		return model.AccessProject{}, errors.New("project is not active")
	}
	if project.RootPath != "" {
		root, err := filepath.Abs(filepath.Clean(project.RootPath))
		if err != nil || !filepath.IsAbs(root) {
			return model.AccessProject{}, errors.New("project rootPath is invalid")
		}
		project.RootPath = root
	}
	return project, nil
}

func reserveProjectDockerResource(projectID uint, resourceType, resourceID string) error {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "__compose_test__" {
		return nil
	}
	var existing model.AccessProjectResource
	err := global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ?", 0, resourceType, resourceID).First(&existing).Error
	if err == nil {
		if existing.ProjectID != projectID {
			return fmt.Errorf("%s %s is already owned by another project", resourceType, resourceID)
		}
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return global.DB.Create(&model.AccessProjectResource{ProjectID: projectID, NodeID: 0, ResourceType: resourceType, ResourceID: resourceID}).Error
}

func readJSONBody(c *gin.Context) ([]byte, map[string]any, error) {
	if c.Request.Body == nil {
		return nil, map[string]any{}, nil
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, nil, err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 || strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/form-data") {
		return body, map[string]any{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	payload := map[string]any{}
	if err := decoder.Decode(&payload); err != nil {
		return body, nil, err
	}
	return body, payload, nil
}

func stringValue(raw any) string {
	if value, ok := raw.(string); ok {
		return strings.TrimSpace(value)
	}
	return ""
}

func stringSlice(raw any) []string {
	items, ok := raw.([]any)
	if !ok {
		return nil
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		if value := stringValue(item); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func uintValueJSON(raw any) uint {
	switch value := raw.(type) {
	case json.Number:
		parsed, _ := strconv.ParseUint(value.String(), 10, 64)
		return uint(parsed)
	case float64:
		if value > 0 {
			return uint(value)
		}
	case string:
		parsed, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
		return uint(parsed)
	}
	return 0
}
