package rbac

import (
	"encoding/json"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

func AuditDecision(c *gin.Context, subjectID uint, action, decision, resourceType, resourceID string, nodeID, projectID uint, reason string) {
	if global.DB == nil {
		return
	}
	subjectType := "user"
	if c != nil {
		if value, ok := c.Get(GinContextRBACSubjectTypeKey); ok {
			if typed, ok := value.(string); ok && typed != "" {
				subjectType = typed
			}
		}
	}
	subjectName := ""
	if subjectID != 0 {
		var user model.AccessUser
		if err := global.DB.Select("username").First(&user, subjectID).Error; err == nil {
			subjectName = user.Username
		}
	}
	event := model.AccessAuditEvent{
		SubjectType: subjectType,
		SubjectID: subjectID,
		SubjectName: subjectName,
		Action: strings.TrimSpace(action),
		Decision: strings.TrimSpace(decision),
		ResourceType: strings.TrimSpace(resourceType),
		ResourceID: strings.TrimSpace(resourceID),
		NodeID: nodeID,
		ProjectID: projectID,
		Reason: strings.TrimSpace(reason),
	}
	if c != nil {
		event.Method = c.Request.Method
		event.Path = c.Request.URL.Path
		event.RemoteIP = c.ClientIP()
	}
	if err := global.DB.Create(&event).Error; err != nil {
		global.LOG.Warnf("write RBAC audit event failed: %v", err)
	}
}

func AuditMutation(c *gin.Context, action, resourceType, resourceID string, metadata map[string]any) {
	userID, _ := CurrentUserID(c)
	serialized := ""
	if len(metadata) != 0 {
		if raw, err := json.Marshal(metadata); err == nil {
			serialized = string(raw)
		}
	}
	event := model.AccessAuditEvent{
		SubjectType: "user", SubjectID: userID, Action: action, Decision: "allow",
		ResourceType: resourceType, ResourceID: resourceID, Metadata: serialized,
		Method: c.Request.Method, Path: c.Request.URL.Path, RemoteIP: c.ClientIP(),
	}
	if value, ok := c.Get(GinContextRBACSubjectTypeKey); ok {
		if typed, ok := value.(string); ok && typed != "" {
			event.SubjectType = typed
		}
	}
	if userID != 0 {
		var user model.AccessUser
		if err := global.DB.Select("username").First(&user, userID).Error; err == nil {
			event.SubjectName = user.Username
		}
	}
	if err := global.DB.Create(&event).Error; err != nil {
		global.LOG.Warnf("write RBAC mutation audit failed: %v", err)
	}
}
