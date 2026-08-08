package rbac

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// RuntimeProjectBindingMiddleware canonicalizes the project boundary for the
// only scoped runtime mutation that may change host paths: /runtimes/update.
//
// Core cannot resolve an Agent runtime numeric ID locally, but ownership uses a
// stable runtime:<name> identity. We therefore require that stable identity to
// have one active owner on the selected node, reject a caller-supplied project
// mismatch, and inject the canonical owner project before the generic runtime
// authorization middleware selects a rootPath. Agent independently verifies
// that the supplied runtime ID actually resolves to this same stable name.
func RuntimeProjectBindingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost || c.Request.URL.Path != "/api/v2/runtimes/update" {
			c.Next()
			return
		}
		if c.GetBool("API_AUTH") || c.GetBool("LOCAL_REQUEST") {
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required for runtime update")
			return
		}
		admin, err := NewEvaluator(global.DB).CanGlobal(userID, "settings.manage")
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate runtime project binding")
			return
		}
		if admin {
			c.Next()
			return
		}

		nodeID, _, err := ResolveRequestNodeID(c)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}
		body, err := io.ReadAll(c.Request.Body)
		if err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse runtime update")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		decoder := json.NewDecoder(bytes.NewReader(body))
		decoder.UseNumber()
		payload := map[string]any{}
		if err := decoder.Decode(&payload); err != nil {
			deny(c, http.StatusBadRequest, "Unable to parse runtime update")
			return
		}
		name := strings.TrimSpace(stringValue(payload["name"]))
		if name == "" || runtimeIDFromCoreRequest(c.Request.URL.Path, payload) == 0 {
			deny(c, http.StatusPreconditionFailed, "Scoped runtime update requires both runtime ID and canonical name")
			return
		}
		stableID := runtimeKey(name)
		var owner model.AccessProjectResource
		err = global.DB.Where(
			"node_id = ? AND resource_type = ? AND resource_id = ? AND state = ?",
			nodeID, "runtime", stableID, model.AccessResourceStateActive,
		).First(&owner).Error
		if errorsIsRecordNotFound(err) {
			deny(c, http.StatusPreconditionFailed, "Runtime project ownership could not be resolved")
			return
		}
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to resolve runtime project ownership")
			return
		}
		if explicit := projectIDFromPayload(payload); explicit != 0 && explicit != owner.ProjectID {
			deny(c, http.StatusPreconditionFailed, "Runtime does not belong to the requested project")
			return
		}
		payload["projectID"] = owner.ProjectID
		delete(payload, "projectId")
		rewritten, err := json.Marshal(payload)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to canonicalize runtime project binding")
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(rewritten))
		c.Request.ContentLength = int64(len(rewritten))
		c.Next()
	}
}

func errorsIsRecordNotFound(err error) bool {
	return err != nil && (err == gorm.ErrRecordNotFound || strings.Contains(err.Error(), gorm.ErrRecordNotFound.Error()))
}
