package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func isDockerOwnershipLifecycleMutation(c *gin.Context, ctx dockerRequestContext) bool {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
	if ctx.ResourceType == "container" && path == "/rename" { return true }
	if ctx.ResourceType == "container" && path == "/operate" {
		return ctx.Permission == "docker.container.delete"
	}
	if ctx.ResourceType == "compose" && path == "/compose/operate" {
		var payload map[string]any
		body, _ := readJSONBody(c)
		_ = json.Unmarshal(body, &payload)
		return strings.EqualFold(stringValue(payload["operation"]), "delete")
	}
	return false
}

// ContinueDockerOwnershipLifecycle keeps name-based Docker/Compose ownership in
// lockstep with rename/delete operations. Scoped destructive operations require
// canonical owned names rather than arbitrary Docker ID prefixes; this removes
// stale grants that could otherwise resurrect when a name is reused later.
func ContinueDockerOwnershipLifecycle(c *gin.Context, nodeID uint, ctx dockerRequestContext, body []byte) {
	path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/containers")
	var payload map[string]any
	if len(bytes.TrimSpace(body)) != 0 {
		if err := json.Unmarshal(body, &payload); err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse Docker ownership mutation")
			return
		}
	}

	if path == "/rename" {
		oldName := strings.TrimSpace(stringValue(payload["name"]))
		newName := strings.TrimSpace(stringValue(payload["newName"]))
		if oldName == "" || newName == "" || oldName == newName {
			deny(c, http.StatusBadRequest, "Container rename requires distinct canonical names")
			return
		}
		owner, err := activeOwnedResourceByCanonicalName(nodeID, "container", oldName)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}
		if err := reserveRenameTarget(owner.ProjectID, nodeID, "container", newName); err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}
		deferred := newDeferredResponseWriter(c.Writer)
		original := c.Writer
		c.Writer = deferred
		c.Next()
		c.Writer = original
		if !creationResponseSucceeded(deferred.Status(), deferred.body.Bytes()) || deferred.overflow {
			rollbackProjectResourceReservation(owner.ProjectID, nodeID, "container", newName)
			if deferred.overflow { deny(c, http.StatusBadGateway, "Docker rename response could not be validated safely"); return }
			_ = deferred.commitTo(original)
			return
		}
		if err := global.DB.Transaction(func(tx *gorm.DB) error {
			result := tx.Where("project_id = ? AND node_id = ? AND resource_type = ? AND resource_id = ? AND state = ?", owner.ProjectID, nodeID, "container", oldName, model.AccessResourceStateActive).
				Delete(&model.AccessProjectResource{})
			if result.Error != nil || result.RowsAffected != 1 { return errors.New("old container ownership changed during rename") }
			result = tx.Model(&model.AccessProjectResource{}).
				Where("project_id = ? AND node_id = ? AND resource_type = ? AND resource_id = ? AND state = ?", owner.ProjectID, nodeID, "container", newName, model.AccessResourceStatePending).
				Update("state", model.AccessResourceStateActive)
			if result.Error != nil || result.RowsAffected != 1 { return errors.New("new container ownership reservation was lost") }
			return nil
		}); err != nil {
			deny(c, http.StatusInternalServerError, "Container was renamed but ownership synchronization failed; administrator repair is required")
			return
		}
		_ = deferred.commitTo(original)
		return
	}

	// Container remove and Compose delete can operate on one or more canonical
	// names. Require every name to have an active ownership row before dispatch.
	names := append([]string(nil), ctx.Targets...)
	if len(names) == 0 {
		deny(c, http.StatusBadRequest, "Docker deletion requires canonical owned names")
		return
	}
	owners, err := activeOwnedResourcesByCanonicalNames(nodeID, ctx.ResourceType, names)
	if err != nil {
		deny(c, http.StatusPreconditionFailed, err.Error())
		return
	}
	deferred := newDeferredResponseWriter(c.Writer)
	original := c.Writer
	c.Writer = deferred
	c.Next()
	c.Writer = original
	if !creationResponseSucceeded(deferred.Status(), deferred.body.Bytes()) || deferred.overflow {
		if deferred.overflow { deny(c, http.StatusBadGateway, "Docker deletion response could not be validated safely"); return }
		_ = deferred.commitTo(original)
		return
	}
	if err := global.DB.Transaction(func(tx *gorm.DB) error {
		for _, owner := range owners {
			result := tx.Where("id = ? AND state = ?", owner.ID, model.AccessResourceStateActive).Delete(&model.AccessProjectResource{})
			if result.Error != nil || result.RowsAffected != 1 { return errors.New("resource ownership changed during deletion") }
		}
		return nil
	}); err != nil {
		deny(c, http.StatusInternalServerError, "Docker resource was deleted but ownership cleanup failed; administrator repair is required")
		return
	}
	_ = deferred.commitTo(original)
}

func reserveRenameTarget(projectID, nodeID uint, resourceType, newName string) error {
	keys := []string{fmt.Sprintf("%d:%s:%s", nodeID, resourceType, newName)}
	sort.Strings(keys)
	release := acquireProjectResourceCreationLock(keys[0])
	defer release()
	created, active, err := reserveProjectResource(projectID, nodeID, resourceType, newName)
	if err != nil { return err }
	if active || !created { return errors.New("rename target already has active ownership") }
	return nil
}

func activeOwnedResourceByCanonicalName(nodeID uint, resourceType, name string) (model.AccessProjectResource, error) {
	var owner model.AccessProjectResource
	err := global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ? AND state = ?", nodeID, resourceType, strings.TrimSpace(name), model.AccessResourceStateActive).First(&owner).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return owner, errors.New("destructive Docker operations require the canonical project-owned resource name")
	}
	return owner, err
}

func activeOwnedResourcesByCanonicalNames(nodeID uint, resourceType string, names []string) ([]model.AccessProjectResource, error) {
	result := make([]model.AccessProjectResource, 0, len(names))
	seen := map[string]struct{}{}
	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" { return nil, errors.New("empty Docker resource name") }
		if _, ok := seen[name]; ok { continue }
		seen[name] = struct{}{}
		owner, err := activeOwnedResourceByCanonicalName(nodeID, resourceType, name)
		if err != nil { return nil, err }
		result = append(result, owner)
	}
	return result, nil
}
