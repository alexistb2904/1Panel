package rbac

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

const (
	auditDenyRecordedKey   = "rbac_deny_audit_recorded"
	auditDenyWindow        = time.Minute
	auditDenyBurst         = 30
	auditLimiterMaxKeys    = 4096
	auditRetention         = 90 * 24 * time.Hour
	auditRetentionInterval = time.Hour
)

type auditWindow struct {
	started time.Time
	count   int
}

var denyAuditLimiter = struct {
	sync.Mutex
	items map[string]auditWindow
}{items: make(map[string]auditWindow)}

var auditRetentionState = struct {
	sync.Mutex
	lastSweep time.Time
}{}

func AuditDecision(c *gin.Context, subjectID uint, action, decision, resourceType, resourceID string, nodeID, projectID uint, reason string) {
	if global.DB == nil { return }
	if strings.EqualFold(strings.TrimSpace(decision), "deny") {
		if c != nil { c.Set(auditDenyRecordedKey, true) }
		if !allowDenyAudit(subjectID, action, resourceType, resourceID, c) { return }
	}
	subjectType := "user"
	if c != nil {
		if value, ok := c.Get(GinContextRBACSubjectTypeKey); ok {
			if typed, ok := value.(string); ok && typed != "" { subjectType = typed }
		}
	}
	subjectName := ""
	if subjectID != 0 {
		var user model.AccessUser
		if err := global.DB.Select("username").First(&user, subjectID).Error; err == nil { subjectName = user.Username }
	}
	event := model.AccessAuditEvent{
		SubjectType: subjectType, SubjectID: subjectID, SubjectName: subjectName,
		Action: strings.TrimSpace(action), Decision: strings.TrimSpace(decision),
		ResourceType: strings.TrimSpace(resourceType), ResourceID: strings.TrimSpace(resourceID),
		NodeID: nodeID, ProjectID: projectID, Reason: strings.TrimSpace(reason),
	}
	if c != nil {
		event.Method = c.Request.Method
		event.Path = c.Request.URL.Path
		event.RemoteIP = c.ClientIP()
	}
	recordAuditEvent(&event)
}

func recordAuditEvent(event *model.AccessAuditEvent) {
	if global.DB == nil || event == nil { return }
	if err := global.DB.Create(event).Error; err != nil {
		global.LOG.Warnf("write RBAC audit event failed: %v", err)
		return
	}
	maybePruneAuditEvents(time.Now())
}

// maybePruneAuditEvents bounds long-term database growth without adding a
// cleanup query to every request. At most one caller per hour performs a
// best-effort 90-day retention sweep. The audit insert remains the source of
// truth; a cleanup failure is logged but never weakens the authorization path.
func maybePruneAuditEvents(now time.Time) {
	auditRetentionState.Lock()
	if !auditRetentionState.lastSweep.IsZero() && now.Sub(auditRetentionState.lastSweep) < auditRetentionInterval {
		auditRetentionState.Unlock()
		return
	}
	auditRetentionState.lastSweep = now
	auditRetentionState.Unlock()

	cutoff := now.Add(-auditRetention)
	if err := global.DB.Where("created_at < ?", cutoff).Delete(&model.AccessAuditEvent{}).Error; err != nil {
		global.LOG.Warnf("prune expired RBAC audit events failed: %v", err)
	}
}

func allowDenyAudit(subjectID uint, action, resourceType, resourceID string, c *gin.Context) bool {
	path := ""
	if c != nil && c.Request != nil { path = c.Request.URL.Path }
	key := fmt.Sprintf("%d|%s|%s|%s|%s", subjectID, action, resourceType, resourceID, path)
	now := time.Now()
	denyAuditLimiter.Lock()
	defer denyAuditLimiter.Unlock()

	if len(denyAuditLimiter.items) >= auditLimiterMaxKeys {
		cutoff := now.Add(-auditDenyWindow)
		for existingKey, window := range denyAuditLimiter.items {
			if window.started.Before(cutoff) { delete(denyAuditLimiter.items, existingKey) }
		}
		if len(denyAuditLimiter.items) >= auditLimiterMaxKeys { return false }
	}

	window, ok := denyAuditLimiter.items[key]
	if !ok || now.Sub(window.started) >= auditDenyWindow {
		denyAuditLimiter.items[key] = auditWindow{started: now, count: 1}
		return true
	}
	if window.count >= auditDenyBurst { return false }
	window.count++
	denyAuditLimiter.items[key] = window
	return true
}

func AuditMutation(c *gin.Context, action, resourceType, resourceID string, metadata map[string]any) {
	userID, _ := CurrentUserID(c)
	serialized := ""
	if len(metadata) != 0 {
		if raw, err := json.Marshal(metadata); err == nil { serialized = string(raw) }
	}
	event := model.AccessAuditEvent{
		SubjectType: "user", SubjectID: userID, Action: action, Decision: "allow",
		ResourceType: resourceType, ResourceID: resourceID, Metadata: serialized,
		Method: c.Request.Method, Path: c.Request.URL.Path, RemoteIP: c.ClientIP(),
	}
	if value, ok := c.Get(GinContextRBACSubjectTypeKey); ok {
		if typed, ok := value.(string); ok && typed != "" { event.SubjectType = typed }
	}
	if userID != 0 {
		var user model.AccessUser
		if err := global.DB.Select("username").First(&user, userID).Error; err == nil { event.SubjectName = user.Username }
	}
	recordAuditEvent(&event)
}
