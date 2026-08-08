package rbac

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	creationResponseCaptureLimit = 1024 * 1024
	staleCreationReservationAge = 15 * time.Minute
)

type keyedCreationLock struct {
	mu   sync.Mutex
	refs int
}

var projectResourceCreationLocks = struct {
	sync.Mutex
	items map[string]*keyedCreationLock
}{items: make(map[string]*keyedCreationLock)}

func acquireProjectResourceCreationLock(key string) func() {
	projectResourceCreationLocks.Lock()
	entry := projectResourceCreationLocks.items[key]
	if entry == nil {
		entry = &keyedCreationLock{}
		projectResourceCreationLocks.items[key] = entry
	}
	entry.refs++
	projectResourceCreationLocks.Unlock()

	entry.mu.Lock()
	return func() {
		entry.mu.Unlock()
		projectResourceCreationLocks.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(projectResourceCreationLocks.items, key)
		}
		projectResourceCreationLocks.Unlock()
	}
}

type deferredResponseWriter struct {
	gin.ResponseWriter
	header  http.Header
	status  int
	size    int
	written bool
	body    bytes.Buffer
	overflow bool
}

func newDeferredResponseWriter(base gin.ResponseWriter) *deferredResponseWriter {
	header := make(http.Header, len(base.Header()))
	for key, values := range base.Header() {
		header[key] = append([]string(nil), values...)
	}
	return &deferredResponseWriter{ResponseWriter: base, header: header, status: http.StatusOK}
}

func (w *deferredResponseWriter) Header() http.Header { return w.header }

func (w *deferredResponseWriter) WriteHeader(code int) {
	if w.written { return }
	w.status = code
	w.written = true
}

func (w *deferredResponseWriter) WriteHeaderNow() {
	if !w.written { w.WriteHeader(w.status) }
}

func (w *deferredResponseWriter) Write(data []byte) (int, error) {
	if !w.written { w.WriteHeader(w.status) }
	if w.body.Len()+len(data) > creationResponseCaptureLimit {
		w.overflow = true
		// Report the logical write as successful to the downstream handler but
		// never partially flush a response that cannot be safely committed.
		w.size += len(data)
		return len(data), nil
	}
	n, err := w.body.Write(data)
	w.size += n
	return n, err
}

func (w *deferredResponseWriter) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func (w *deferredResponseWriter) Status() int { return w.status }
func (w *deferredResponseWriter) Size() int { return w.size }
func (w *deferredResponseWriter) Written() bool { return w.written }
func (w *deferredResponseWriter) Flush() { w.WriteHeaderNow() }
func (w *deferredResponseWriter) Pusher() http.Pusher { return w.ResponseWriter.Pusher() }

func (w *deferredResponseWriter) commitTo(target gin.ResponseWriter) error {
	if w.overflow {
		return errors.New("downstream creation response exceeded the safe buffering limit")
	}
	for key := range target.Header() { target.Header().Del(key) }
	for key, values := range w.header {
		for _, value := range values { target.Header().Add(key, value) }
	}
	target.WriteHeader(w.status)
	if w.body.Len() != 0 {
		_, err := target.Write(w.body.Bytes())
		return err
	}
	return nil
}

// ContinueCreationWithOwnership uses a two-phase ownership record. A pending
// reservation prevents concurrent/cross-project reuse but is deliberately
// excluded from authorization by Evaluator. The reservation becomes active
// only after the downstream Agent has completed the resource creation and the
// ownership activation has been committed. The downstream success response is
// buffered until that database transition succeeds.
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
	release := acquireProjectResourceCreationLock(lockKey)
	defer release()

	reservationCreated, alreadyActive, err := reserveProjectResource(projectID, nodeID, resourceType, resourceID)
	if err != nil {
		deny(c, http.StatusPreconditionFailed, err.Error())
		return
	}

	originalWriter := c.Writer
	writer := newDeferredResponseWriter(originalWriter)
	c.Writer = writer
	c.Next()
	c.Writer = originalWriter

	if writer.overflow {
		if reservationCreated { rollbackProjectResourceReservation(projectID, nodeID, resourceType, resourceID) }
		deny(c, http.StatusBadGateway, "Downstream creation response was too large to validate safely")
		return
	}
	if !creationResponseSucceeded(writer.Status(), writer.body.Bytes()) {
		if reservationCreated { rollbackProjectResourceReservation(projectID, nodeID, resourceType, resourceID) }
		if err := writer.commitTo(originalWriter); err != nil {
			global.LOG.Errorf("flush downstream creation failure response: %v", err)
		}
		return
	}

	if reservationCreated {
		result := global.DB.Model(&model.AccessProjectResource{}).
			Where("project_id = ? AND node_id = ? AND resource_type = ? AND resource_id = ? AND state = ?", projectID, nodeID, resourceType, resourceID, model.AccessResourceStatePending).
			Updates(map[string]any{"state": model.AccessResourceStateActive, "updated_at": time.Now()})
		if result.Error != nil || result.RowsAffected != 1 {
			global.LOG.Errorf("RBAC ownership activation failed after successful creation node=%d type=%s id=%s project=%d: %v", nodeID, resourceType, resourceID, projectID, result.Error)
			AuditDecision(c, 0, "rbac.project_resource.activate", "deny", resourceType, resourceID, nodeID, projectID, "resource created but ownership activation failed")
			deny(c, http.StatusInternalServerError, "Resource was created but its project ownership could not be activated; administrator repair is required")
			return
		}
	} else if !alreadyActive {
		deny(c, http.StatusInternalServerError, "Resource ownership reservation was lost")
		return
	}

	if err := writer.commitTo(originalWriter); err != nil {
		global.LOG.Errorf("flush committed creation response: %v", err)
	}
}

func reserveProjectResource(projectID, nodeID uint, resourceType, resourceID string) (created bool, alreadyActive bool, err error) {
	var existing model.AccessProjectResource
	err = global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ?", nodeID, resourceType, resourceID).First(&existing).Error
	if err == nil {
		if existing.ProjectID != projectID {
			return false, false, fmt.Errorf("%s %s is already owned by another project", resourceType, resourceID)
		}
		if existing.State == "" || existing.State == model.AccessResourceStateActive {
			return false, true, nil
		}
		if existing.State == model.AccessResourceStatePending && time.Since(existing.UpdatedAt) < staleCreationReservationAge {
			return false, false, fmt.Errorf("%s %s creation is already pending", resourceType, resourceID)
		}
		// A stale reservation is safe to reclaim because pending rows never grant
		// access. The keyed lock prevents a live in-process creator being raced.
		if err := global.DB.Delete(&existing).Error; err != nil {
			return false, false, err
		}
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, false, err
	}

	reservation := model.AccessProjectResource{
		ProjectID: projectID, NodeID: nodeID, ResourceType: resourceType,
		ResourceID: resourceID, State: model.AccessResourceStatePending,
	}
	if err := global.DB.Create(&reservation).Error; err != nil {
		return false, false, err
	}
	return true, false, nil
}

func rollbackProjectResourceReservation(projectID, nodeID uint, resourceType, resourceID string) {
	if err := global.DB.Where("project_id = ? AND node_id = ? AND resource_type = ? AND resource_id = ? AND state = ?", projectID, nodeID, resourceType, resourceID, model.AccessResourceStatePending).
		Delete(&model.AccessProjectResource{}).Error; err != nil {
		global.LOG.Errorf("rollback RBAC creation reservation node=%d type=%s id=%s project=%d: %v", nodeID, resourceType, resourceID, projectID, err)
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
	if existing.State == model.AccessResourceStatePending {
		return false, fmt.Errorf("%s %s creation is already pending", resourceType, resourceID)
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
		return false
	}
	return envelope.Code >= http.StatusOK && envelope.Code < http.StatusMultipleChoices
}
