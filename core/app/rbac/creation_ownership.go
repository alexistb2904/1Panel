package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const creationResponseCaptureLimit = 64 * 1024

var projectResourceCreationLocks sync.Map

type creationCaptureWriter struct {
	gin.ResponseWriter
	captured bytes.Buffer
}

func (w *creationCaptureWriter) Write(data []byte) (int, error) {
	w.capture(data)
	return w.ResponseWriter.Write(data)
}

func (w *creationCaptureWriter) WriteString(value string) (int, error) {
	w.capture([]byte(value))
	return w.ResponseWriter.WriteString(value)
}

func (w *creationCaptureWriter) capture(data []byte) {
	if w.captured.Len() >= creationResponseCaptureLimit { return }
	remaining := creationResponseCaptureLimit - w.captured.Len()
	if len(data) > remaining { data = data[:remaining] }
	_, _ = w.captured.Write(data)
}

// ContinueCreationWithOwnership serializes creation of a concrete resource,
// rejects a conflicting existing owner, forwards the request, and persists
// ownership only after the downstream Agent reports success. The Agent receives
// the proposed resource ID directly in trusted Core headers, so no pre-created
// ownership row is required for authorization.
func ContinueCreationWithOwnership(c *gin.Context, projectID, nodeID uint, resourceType, resourceID string) {
	resourceType = strings.TrimSpace(resourceType)
	resourceID = strings.TrimSpace(resourceID)
	if resourceType == "" || resourceID == "" {
		deny(c, http.StatusPreconditionFailed, "A stable resource identity is required for project ownership")
		return
	}
	if resourceID == "__compose_test__" {
		c.Next()
		return
	}

	lockKey := fmt.Sprintf("%d:%s:%s", nodeID, resourceType, resourceID)
	value, _ := projectResourceCreationLocks.LoadOrStore(lockKey, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	alreadyOwned, err := projectResourceOwnedBy(projectID, nodeID, resourceType, resourceID)
	if err != nil {
		deny(c, http.StatusPreconditionFailed, err.Error())
		return
	}

	writer := &creationCaptureWriter{ResponseWriter: c.Writer}
	c.Writer = writer
	c.Next()
	if alreadyOwned || !creationResponseSucceeded(writer.Status(), writer.captured.Bytes()) {
		return
	}
	resource := model.AccessProjectResource{ProjectID: projectID, NodeID: nodeID, ResourceType: resourceType, ResourceID: resourceID}
	if err := global.DB.Create(&resource).Error; err != nil {
		// The resource now exists but is deliberately not exposed to restricted
		// identities without an ownership row. Surface this loudly for an admin
		// to repair rather than granting ambiguous access.
		global.LOG.Errorf("RBAC ownership commit failed after successful creation node=%d type=%s id=%s project=%d: %v", nodeID, resourceType, resourceID, projectID, err)
		AuditDecision(c, 0, "rbac.project_resource.commit", "deny", resourceType, resourceID, nodeID, projectID, "resource created but ownership persistence failed")
	}
}

func projectResourceOwnedBy(projectID, nodeID uint, resourceType, resourceID string) (bool, error) {
	var existing model.AccessProjectResource
	err := global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ?", nodeID, resourceType, resourceID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) { return false, nil }
	if err != nil { return false, err }
	if existing.ProjectID != projectID {
		return false, fmt.Errorf("%s %s is already owned by another project", resourceType, resourceID)
	}
	return true, nil
}

func creationResponseSucceeded(status int, body []byte) bool {
	if status < http.StatusOK || status >= http.StatusMultipleChoices { return false }
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 { return true }
	var envelope struct {
		Code int `json:"code"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		// Creation endpoints should return the standard 1Panel envelope. Unknown
		// responses are fail-closed and do not create an ownership grant.
		return false
	}
	return envelope.Code >= http.StatusOK && envelope.Code < http.StatusMultipleChoices
}
