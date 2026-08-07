package rbac

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

// DockerAuthorizationMiddlewareV2 is the production path for scoped Docker
// authorization. It mirrors the real Agent router and leaves unclassified
// engine-wide operations administrator-only by default.
func DockerAuthorizationMiddlewareV2() gin.HandlerFunc {
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

		if node := requestedRBACNode(c); node != "" && node != "local" {
			deny(c, http.StatusPreconditionFailed, "Scoped Docker access to remote nodes is not enabled yet")
			return
		}

		ctx, body, err := classifyDockerRequestV2(c)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse Docker authorization target")
			return
		}
		if body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}
		if ctx.Permission == "" {
			deny(c, http.StatusPreconditionFailed, "This Docker operation is administrator-only")
			return
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

func classifyDockerRequestV2(c *gin.Context) (dockerRequestContext, []byte, error) {
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

	if strings.HasPrefix(path, "/stats/") && method == http.MethodGet {
		id := strings.TrimSpace(strings.TrimPrefix(path, "/stats/"))
		return dockerRequestContext{Permission: "docker.container.stats", ResourceType: "container", Targets: []string{id}}, body, nil
	}

	switch path {
	case "/search", "/list", "/list/stats":
		return dockerRequestContext{Permission: "docker.container.view", ResourceType: "container"}, body, nil
	case "/info", "/item/stats":
		return dockerRequestContext{Permission: "docker.container.view", ResourceType: "container", Targets: []string{value("name")}}, body, nil
	case "/users":
		return dockerRequestContext{Permission: "docker.container.exec", ResourceType: "container", Targets: []string{value("name")}}, body, nil
	case "/operate":
		permission := ""
		switch strings.ToLower(value("operation")) {
		case "start", "up", "unpause":
			permission = "docker.container.start"
		case "stop", "pause", "kill":
			permission = "docker.container.stop"
		case "restart":
			permission = "docker.container.restart"
		case "remove", "delete":
			permission = "docker.container.delete"
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
	case "/clean/log":
		return dockerRequestContext{Permission: "docker.container.edit", ResourceType: "container", Targets: []string{value("name")}}, body, nil
	case "/download/log":
		containerType := strings.ToLower(value("containerType"))
		if containerType == "" || containerType == "container" {
			return dockerRequestContext{Permission: "docker.container.logs", ResourceType: "container", Targets: []string{value("container")}}, body, nil
		}
		return dockerRequestContext{}, body, nil
	case "/search/log":
		if method == http.MethodGet {
			target := strings.TrimSpace(c.Query("container"))
			if target == "" {
				target = strings.TrimSpace(c.Query("name"))
			}
			return dockerRequestContext{Permission: "docker.container.logs", ResourceType: "container", Targets: []string{target}}, body, nil
		}
	case "/inspect":
		typeName := strings.ToLower(value("type"))
		if typeName == "container" {
			return dockerRequestContext{Permission: "docker.container.view", ResourceType: "container", Targets: []string{value("id")}}, body, nil
		}
		if typeName == "compose" {
			return dockerRequestContext{Permission: "docker.compose.view", ResourceType: "compose", Targets: []string{value("id")}}, body, nil
		}
	case "/files/search", "/files/content", "/files/size", "/files/del", "/files/download":
		return dockerRequestContext{Permission: "docker.container.exec", ResourceType: "container", Targets: []string{value("containerID")}}, body, nil
	case "":
		if method == http.MethodPost {
			return dockerRequestContext{Permission: "docker.container.create", ResourceType: "container", Targets: []string{value("name")}, ProjectID: projectID, Creating: true}, body, nil
		}

	case "/compose/search":
		return dockerRequestContext{Permission: "docker.compose.view", ResourceType: "compose"}, body, nil
	case "/compose/env":
		return dockerRequestContext{Permission: "docker.compose.env.view", ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose/operate":
		permission := ""
		switch strings.ToLower(value("operation")) {
		case "stop":
			permission = "docker.compose.stop"
		case "delete", "down":
			permission = "docker.compose.delete"
		case "up", "start", "restart", "rebuild":
			permission = "docker.compose.deploy"
		}
		return dockerRequestContext{Permission: permission, ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose/clean/log", "/compose/pin":
		return dockerRequestContext{Permission: "docker.compose.edit", ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose/update":
		return dockerRequestContext{Permission: "docker.compose.edit", ResourceType: "compose", Targets: []string{value("name")}}, body, nil
	case "/compose":
		if method == http.MethodPost {
			return dockerRequestContext{Permission: "docker.compose.create", ResourceType: "compose", Targets: []string{value("name")}, ProjectID: projectID, Creating: true}, body, nil
		}
	case "/compose/test":
		if projectID == 0 {
			return dockerRequestContext{}, body, errors.New("projectID is required")
		}
		return dockerRequestContext{Permission: "docker.compose.create", ResourceType: "compose", ProjectID: projectID, Creating: true, Targets: []string{"__compose_test__"}}, body, nil
	}
	return dockerRequestContext{}, body, nil
}

func requestedRBACNode(c *gin.Context) string {
	node := strings.TrimSpace(c.Query("operateNode"))
	if node == "" || node == "undefined" {
		node = strings.TrimSpace(c.GetHeader("CurrentNode"))
	}
	return node
}

func ensureActiveProject(id uint) (model.AccessProject, error) {
	var project model.AccessProject
	if err := global.DB.First(&project, id).Error; err != nil {
		return project, err
	}
	if project.Status != "active" {
		return project, errors.New("project is not active")
	}
	return project, nil
}
