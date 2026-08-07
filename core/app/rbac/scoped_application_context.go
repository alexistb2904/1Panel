package rbac

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type scopedApplicationRequest struct {
	Permission   string
	ResourceType string
	ResourceID   string
	ProjectID    uint
	Creating     bool
	NeedsRoot    bool
}

func ScopedApplicationAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		if !strings.HasPrefix(path, "/api/v2/databases") && !strings.HasPrefix(path, "/api/v2/runtimes") {
			c.Next()
			return
		}
		clearAgentRBACHeaders(c)
		for _, key := range []string{HeaderRBACProjectID, HeaderRBACProjectRoot, HeaderRBACRestricted} {
			c.Request.Header.Del(key)
		}
		if c.GetBool("API_AUTH") || c.GetBool("LOCAL_REQUEST") {
			resourceType := "database"
			if strings.HasPrefix(path, "/api/v2/runtimes") {
				resourceType = "runtime"
			}
			setAgentRBACHeaders(c, 0, "platform.internal", resourceType, ResourceFilter{All: true})
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required")
			return
		}
		evaluator := NewEvaluator(global.DB)
		admin, err := evaluator.Can(userID, "settings.manage", ResourceContext{})
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate scoped application access")
			return
		}
		if admin {
			setAgentRBACHeaders(c, userID, "administrator", "application", ResourceFilter{All: true})
			c.Next()
			return
		}
		nodeID, _, err := ResolveRequestNodeID(c)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}
		req, body, err := classifyScopedApplicationRequest(c)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse scoped application target")
			return
		}
		if req.Permission == "" || req.ResourceType == "" {
			deny(c, http.StatusPreconditionFailed, "This operation is restricted to administrators")
			return
		}
		if body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}
		if req.Creating {
			project, err := authorizeProjectResourceCreation(evaluator, userID, nodeID, req)
			if err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			if err := reserveProjectResource(project.ID, nodeID, req.ResourceType, req.ResourceID); err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			setAgentRBACHeaders(c, userID, req.Permission, req.ResourceType, ResourceFilter{IDs: []string{req.ResourceID}})
			setProjectTransportHeaders(c, project)
			c.Next()
			return
		}
		filter, err := evaluator.AccessibleResourceIDs(userID, req.Permission, req.ResourceType, nodeID)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to resolve resource scope")
			return
		}
		setAgentRBACHeaders(c, userID, req.Permission, req.ResourceType, filter)
		c.Request.Header.Set(HeaderRBACRestricted, "1")
		if req.NeedsRoot {
			project, err := projectForScopedResource(nodeID, req.ResourceType, req.ResourceID, req.ProjectID)
			if err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			allowed, err := evaluator.Can(userID, req.Permission, ResourceContext{NodeID: nodeID, ProjectID: project.ID, Type: req.ResourceType, ID: req.ResourceID})
			if err != nil || !allowed {
				deny(c, http.StatusPreconditionFailed, "Resource is not writable in the selected project")
				return
			}
			setProjectTransportHeaders(c, project)
		}
		c.Next()
	}
}

func classifyScopedApplicationRequest(c *gin.Context) (scopedApplicationRequest, []byte, error) {
	body, payload, err := readJSONBody(c)
	if err != nil {
		return scopedApplicationRequest{}, body, err
	}
	if strings.HasPrefix(c.Request.URL.Path, "/api/v2/databases") {
		return classifyDatabaseCoreRequest(c.Request.Method, c.Request.URL.Path, payload), body, nil
	}
	return classifyRuntimeCoreRequest(c.Request.Method, c.Request.URL.Path, payload), body, nil
}

func classifyDatabaseCoreRequest(method, path string, payload map[string]any) scopedApplicationRequest {
	value := func(key string) string { return stringValue(payload[key]) }
	projectID := projectIDFromPayload(payload)
	instance := value("database")
	name := value("name")
	id := uintValueJSON(payload["id"])
	kind := strings.ToLower(value("type"))
	switch path {
	case "/api/v2/databases/search", "/api/v2/databases/pg/search", "/api/v2/databases/mongodb/search":
		return scopedApplicationRequest{Permission: "database.view", ResourceType: "database"}
	case "/api/v2/databases":
		if method == http.MethodPost && instance != "" && name != "" {
			return scopedApplicationRequest{Permission: "database.create", ResourceType: "database", ResourceID: databaseKey("mysql", instance, name), ProjectID: projectID, Creating: true}
		}
	case "/api/v2/databases/pg":
		if method == http.MethodPost && instance != "" && name != "" {
			return scopedApplicationRequest{Permission: "database.create", ResourceType: "database", ResourceID: databaseKey("postgresql", instance, name), ProjectID: projectID, Creating: true}
		}
	case "/api/v2/databases/mongodb":
		if method == http.MethodPost && instance != "" && name != "" {
			return scopedApplicationRequest{Permission: "database.create", ResourceType: "database", ResourceID: databaseKey("mongodb", instance, name), ProjectID: projectID, Creating: true}
		}
	}
	permission := ""
	switch path {
	case "/api/v2/databases/del/check":
		permission = "database.view"
	case "/api/v2/databases/del":
		permission = "database.delete"
	case "/api/v2/databases/description/update", "/api/v2/databases/change/access", "/api/v2/databases/grants", "/api/v2/databases/grants/del", "/api/v2/databases/users":
		permission = "database.update"
	case "/api/v2/databases/change/password":
		permission = "database.credentials.rotate"
	case "/api/v2/databases/pg/del/check", "/api/v2/databases/mongodb/del/check":
		permission = "database.view"
	case "/api/v2/databases/pg/del", "/api/v2/databases/mongodb/del":
		permission = "database.delete"
	case "/api/v2/databases/pg/description", "/api/v2/databases/pg/bind", "/api/v2/databases/pg/privileges", "/api/v2/databases/mongodb/description", "/api/v2/databases/mongodb/bind", "/api/v2/databases/mongodb/privileges/change":
		permission = "database.update"
	case "/api/v2/databases/pg/password", "/api/v2/databases/mongodb/password":
		permission = "database.credentials.rotate"
	case "/api/v2/databases/mongodb/privileges":
		permission = "database.view"
	default:
		return scopedApplicationRequest{}
	}
	resourceID := ""
	if id != 0 {
		resourceID = strconv.FormatUint(uint64(id), 10)
	} else if instance != "" && name != "" {
		switch {
		case strings.Contains(path, "/pg/"):
			resourceID = databaseKey("postgresql", instance, name)
		case strings.Contains(path, "/mongodb/"):
			resourceID = databaseKey("mongodb", instance, name)
		default:
			resourceID = databaseKey(normalizeDatabaseKind(kind), instance, name)
		}
	}
	return scopedApplicationRequest{Permission: permission, ResourceType: "database", ResourceID: resourceID, ProjectID: projectID}
}

func classifyRuntimeCoreRequest(method, path string, payload map[string]any) scopedApplicationRequest {
	projectID := projectIDFromPayload(payload)
	name := stringValue(payload["name"])
	if path == "/api/v2/runtimes/search" && method == http.MethodPost {
		return scopedApplicationRequest{Permission: "runtime.view", ResourceType: "runtime"}
	}
	if path == "/api/v2/runtimes" && method == http.MethodPost {
		return scopedApplicationRequest{Permission: "runtime.create", ResourceType: "runtime", ResourceID: runtimeKey(name), ProjectID: projectID, Creating: true, NeedsRoot: true}
	}
	id := runtimeIDFromCoreRequest(path, payload)
	resourceID := ""
	if id != 0 {
		resourceID = strconv.FormatUint(uint64(id), 10)
	}
	permission := ""
	needsRoot := false
	switch path {
	case "/api/v2/runtimes/del":
		permission = "runtime.delete"
	case "/api/v2/runtimes/update":
		permission, needsRoot = "runtime.edit", hasRuntimeHostPathMutation(payload)
	case "/api/v2/runtimes/operate":
		switch strings.ToLower(stringValue(payload["operate"])) {
		case "start":
			permission = "runtime.start"
		case "stop":
			permission = "runtime.stop"
		case "restart":
			permission = "runtime.restart"
		}
	case "/api/v2/runtimes/node/modules":
		permission = "runtime.view"
	case "/api/v2/runtimes/node/modules/operate", "/api/v2/runtimes/php/config", "/api/v2/runtimes/php/update", "/api/v2/runtimes/php/fpm/config", "/api/v2/runtimes/php/extensions/install", "/api/v2/runtimes/php/extensions/uninstall", "/api/v2/runtimes/supervisor/process", "/api/v2/runtimes/supervisor/process/file", "/api/v2/runtimes/remark":
		permission = "runtime.edit"
	case "/api/v2/runtimes/php/file":
		permission = "runtime.view"
	case "/api/v2/runtimes/php/container/update":
		permission, needsRoot = "runtime.edit", true
	default:
		segments := splitPath(strings.TrimPrefix(path, "/api/v2/runtimes"))
		if len(segments) == 1 && id != 0 && method == http.MethodGet {
			permission = "runtime.view"
		} else if strings.HasPrefix(path, "/api/v2/runtimes/installed/delete/check/") {
			permission = "runtime.view"
		} else if (strings.Contains(path, "/php/") || strings.Contains(path, "/supervisor/process/")) && method == http.MethodGet {
			permission = "runtime.view"
		}
	}
	if permission == "" {
		return scopedApplicationRequest{}
	}
	return scopedApplicationRequest{Permission: permission, ResourceType: "runtime", ResourceID: resourceID, ProjectID: projectID, NeedsRoot: needsRoot}
}

func authorizeProjectResourceCreation(evaluator *Evaluator, userID, nodeID uint, req scopedApplicationRequest) (model.AccessProject, error) {
	if req.ProjectID == 0 || strings.TrimSpace(req.ResourceID) == "" {
		return model.AccessProject{}, errors.New("projectID and a stable resource name are required")
	}
	allowed, err := evaluator.Can(userID, req.Permission, ResourceContext{NodeID: nodeID, ProjectID: req.ProjectID, Type: "project", ID: strconv.FormatUint(uint64(req.ProjectID), 10)})
	if err != nil || !allowed {
		return model.AccessProject{}, errors.New("resource creation is not allowed in this project")
	}
	var project model.AccessProject
	if err := global.DB.First(&project, req.ProjectID).Error; err != nil {
		return model.AccessProject{}, errors.New("project does not exist")
	}
	if project.Status != "active" {
		return model.AccessProject{}, errors.New("project is not active")
	}
	return project, nil
}

func reserveProjectResource(projectID, nodeID uint, resourceType, resourceID string) error {
	resourceID = strings.TrimSpace(resourceID)
	var existing model.AccessProjectResource
	err := global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ?", nodeID, resourceType, resourceID).First(&existing).Error
	if err == nil {
		if existing.ProjectID != projectID {
			return fmt.Errorf("%s %s is already owned by another project", resourceType, resourceID)
		}
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return global.DB.Create(&model.AccessProjectResource{ProjectID: projectID, NodeID: nodeID, ResourceType: resourceType, ResourceID: resourceID}).Error
}

func projectForScopedResource(nodeID uint, resourceType, resourceID string, explicitProjectID uint) (model.AccessProject, error) {
	var membership model.AccessProjectResource
	query := global.DB.Where("node_id = ? AND resource_type = ?", nodeID, resourceType)
	if explicitProjectID != 0 {
		query = query.Where("project_id = ?", explicitProjectID)
	}
	if resourceID != "" {
		query = query.Where("resource_id = ?", resourceID)
	}
	if err := query.First(&membership).Error; err != nil {
		return model.AccessProject{}, errors.New("resource project ownership could not be resolved")
	}
	var project model.AccessProject
	if err := global.DB.First(&project, membership.ProjectID).Error; err != nil || project.Status != "active" {
		return model.AccessProject{}, errors.New("resource project is not active")
	}
	return project, nil
}

func setProjectTransportHeaders(c *gin.Context, project model.AccessProject) {
	c.Request.Header.Set(HeaderRBACRestricted, "1")
	c.Request.Header.Set(HeaderRBACProjectID, strconv.FormatUint(uint64(project.ID), 10))
	if strings.TrimSpace(project.RootPath) != "" {
		c.Request.Header.Set(HeaderRBACProjectRoot, project.RootPath)
	}
}

func projectIDFromPayload(payload map[string]any) uint {
	if id := uintValueJSON(payload["projectID"]); id != 0 {
		return id
	}
	return uintValueJSON(payload["projectId"])
}

func runtimeIDFromCoreRequest(path string, payload map[string]any) uint {
	for _, key := range []string{"id", "ID", "runtimeID", "runtimeId"} {
		if id := uintValueJSON(payload[key]); id != 0 {
			return id
		}
	}
	for _, segment := range splitPath(strings.TrimPrefix(path, "/api/v2/runtimes")) {
		if id, err := strconv.ParseUint(segment, 10, 64); err == nil && id > 0 {
			return uint(id)
		}
	}
	return 0
}

func hasRuntimeHostPathMutation(payload map[string]any) bool {
	if stringValue(payload["codeDir"]) != "" {
		return true
	}
	volumes, ok := payload["volumes"].([]any)
	return ok && len(volumes) > 0
}

func databaseKey(kind, instance, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.TrimSpace(instance) + ":" + strings.TrimSpace(name)
}
func runtimeKey(name string) string { return "runtime:" + strings.TrimSpace(name) }
func normalizeDatabaseKind(kind string) string {
	switch kind {
	case "postgresql", "postgresql-cluster":
		return "postgresql"
	case "mongodb":
		return "mongodb"
	default:
		return "mysql"
	}
}
