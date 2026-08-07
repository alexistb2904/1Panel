package rbac

import (
	"bytes"
	"errors"
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

// DockerAuthorizationMiddlewareV3 extends V2 to registered remote nodes. The
// same Agent-side anti-escalation policy is used after Core computes the node-
// specific project/resource scope.
func DockerAuthorizationMiddlewareV3() gin.HandlerFunc {
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
		nodeID, _, err := ResolveRequestNodeID(c)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
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
			project, err := authorizeDockerProjectCreationAtNode(evaluator, userID, nodeID, ctx)
			if err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			setAgentRBACHeaders(c, userID, ctx.Permission, ctx.ResourceType, ResourceFilter{IDs: ctx.Targets})
			c.Request.Header.Set(HeaderRBACRestricted, "1")
			c.Request.Header.Set(HeaderRBACProjectID, strconv.FormatUint(uint64(project.ID), 10))
			c.Request.Header.Set(HeaderRBACProjectRoot, project.RootPath)
			if err := reserveProjectDockerResourceAtNode(project.ID, nodeID, ctx.ResourceType, ctx.Targets[0]); err != nil {
				deny(c, http.StatusPreconditionFailed, err.Error())
				return
			}
			c.Next()
			return
		}
		filter, err := evaluator.AccessibleResourceIDs(userID, ctx.Permission, ctx.ResourceType, nodeID)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to resolve Docker resource scope")
			return
		}
		setAgentRBACHeaders(c, userID, ctx.Permission, ctx.ResourceType, filter)
		c.Request.Header.Set(HeaderRBACRestricted, "1")
		c.Next()
	}
}

func authorizeDockerProjectCreationAtNode(evaluator *Evaluator, userID, nodeID uint, ctx dockerRequestContext) (model.AccessProject, error) {
	if ctx.ProjectID == 0 || len(ctx.Targets) == 0 || strings.TrimSpace(ctx.Targets[0]) == "" {
		return model.AccessProject{}, errors.New("Docker creation requires a projectID and a stable resource name")
	}
	allowed, err := evaluator.Can(userID, ctx.Permission, ResourceContext{NodeID: nodeID, ProjectID: ctx.ProjectID, Type: "project", ID: strconv.FormatUint(uint64(ctx.ProjectID), 10)})
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
		if err != nil || !filepath.IsAbs(root) || root == string(filepath.Separator) {
			return model.AccessProject{}, errors.New("project rootPath is invalid")
		}
		project.RootPath = root
	}
	return project, nil
}

func reserveProjectDockerResourceAtNode(projectID, nodeID uint, resourceType, resourceID string) error {
	resourceID = strings.TrimSpace(resourceID)
	if resourceID == "__compose_test__" {
		return nil
	}
	var existing model.AccessProjectResource
	err := global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ?", nodeID, resourceType, resourceID).First(&existing).Error
	if err == nil {
		if existing.ProjectID != projectID {
			return errors.New("Docker resource is already owned by another project")
		}
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return global.DB.Create(&model.AccessProjectResource{ProjectID: projectID, NodeID: nodeID, ResourceType: resourceType, ResourceID: resourceID}).Error
}
