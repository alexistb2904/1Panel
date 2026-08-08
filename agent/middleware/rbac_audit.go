package middleware

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/gin-gonic/gin"
)

const rbacAuditCaptureLimit = 4096

type rbacAuditWriter struct {
	gin.ResponseWriter
	captured bytes.Buffer
}

func (w *rbacAuditWriter) Write(data []byte) (int, error) {
	if w.captured.Len() < rbacAuditCaptureLimit {
		remaining := rbacAuditCaptureLimit - w.captured.Len()
		if remaining > len(data) {
			remaining = len(data)
		}
		_, _ = w.captured.Write(data[:remaining])
	}
	return w.ResponseWriter.Write(data)
}

// RBACSecurityAudit complements the Core decision ledger with denials produced
// by the Agent's second security barrier (filesystem canonicalisation, Docker
// anti-escalation, target re-resolution, etc.). It never captures request
// bodies and only parses a bounded prefix of the response.
func RBACSecurityAudit() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := strings.TrimSpace(c.GetHeader("X-Panel-RBAC-User-ID"))
		permission := strings.TrimSpace(c.GetHeader("X-Panel-RBAC-Permission"))
		if userID == "" || permission == "" {
			c.Next()
			return
		}
		writer := &rbacAuditWriter{ResponseWriter: c.Writer}
		c.Writer = writer
		c.Next()

		var response struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(writer.captured.Bytes(), &response); err != nil || response.Code < 400 {
			return
		}
		global.LOG.Warnf(
			"security_audit=rbac_denied user_id=%s permission=%s resource_type=%s method=%s path=%s code=%d reason=%q",
			userID,
			permission,
			strings.TrimSpace(c.GetHeader("X-Panel-RBAC-Resource-Type")),
			c.Request.Method,
			c.Request.URL.Path,
			response.Code,
			response.Message,
		)
	}
}
