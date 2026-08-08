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
		admin, err := evaluator.CanGlobal(userID, "settings.manage")
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
		if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
		if ctx.Permission == "" {
			deny(c, http.StatusPreconditionFailed, "This Docker operation is administrator-only")
			return
		}
		if ctx.Creating {
			project, err := authorizeDockerProjectCreationAtNode(evaluator, userID, nodeID, ctx)
			if err != nil { deny(c, http.StatusPreconditionFailed, err.Error()); return }
			resourceID := ctx.Targets[0]
			if resourceID != "__compose_test__" {
				if _, err := projectResourceOwnedBy(project.ID, nodeID, ctx.ResourceType, resourceID); err != nil {
					deny(c, http.StatusPreconditionFailed, err.Error())
					return
				}
			}
			setAgentRBACHeaders(c, userID, ctx.Permission, ctx.ResourceType, ResourceFilter{IDs: ctx.Targets})
			if err := setProjectTransportHeaders(c, project, nodeID); err != nil { deny(c, http.StatusPreconditionFailed, err.Error()); return }
			ContinueCreationWithOwnership(c, project.ID, nodeID, ctx.ResourceType, resourceID)
			return
		}
		filter, err := evaluator.AccessibleResourceIDs(userID, ctx.Permission, ctx.ResourceType, nodeID)
		if err != nil { deny(c, http.StatusInternalServerError, "Unable to resolve Docker resource scope"); return }
		setAgentRBACHeaders(c, userID, ctx.Permission, ctx.ResourceType, filter)
		c.Request.Header.Set(HeaderRBACRestricted, "1")
		if isDockerOwnershipLifecycleMutation(c, ctx) {
			if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
			ContinueDockerOwnershipLifecycle(c, nodeID, ctx, body)
			return
		}
		c.Next()
	}
}

func authorizeDockerProjectCreationAtNode(evaluator *Evaluator, userID, nodeID uint, ctx dockerRequestContext) (model.AccessProject, error) {
	if ctx.ProjectID == 0 || len(ctx.Targets) == 0 || strings.TrimSpace(ctx.Targets[0]) == "" {
		return model.AccessProject{}, errors.New("Docker creation requires a projectID and a stable resource name")
	}
	allowed, err := evaluator.Can(userID, ctx.Permission, ResourceContext{NodeID: nodeID, ProjectID: ctx.ProjectID, Type: "project", ID: strconv.FormatUint(uint64(ctx.ProjectID), 10)})
	if err != nil || !allowed {
		return model.AccessProject{}, errors.New("Docker creation is not allowed for this project on the selected node")
	}
	var project model.AccessProject
	if err := global.DB.First(&project, ctx.ProjectID).Error; err != nil { return model.AccessProject{}, errors.New("project does not exist") }
	if project.Status != "active" { return model.AccessProject{}, errors.New("project is not active") }
	return project, nil
}
