package rbac

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

const headerRBACDeletedResourceIdentity = "X-Panel-RBAC-Deleted-Resource-Identity"

type deletedResourceIdentity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ResourceDeletionOwnershipMiddleware synchronizes stable-name ownership after
// Website/Database/Runtime deletion. Agent resolves the canonical identity
// before deleting its local record and returns it in a trusted response header.
// Core buffers the downstream response, removes ownership only on business
// success, strips the internal header and then releases the response.
func ResourceDeletionOwnershipMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		expectedType, ok := deletionResourceType(c.Request.URL.Path, c.Request.Method)
		if !ok {
			c.Next()
			return
		}
		nodeID, _, err := ResolveRequestNodeID(c)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}

		original := c.Writer
		deferred := newDeferredResponseWriter(original)
		c.Writer = deferred
		c.Next()
		c.Writer = original

		encoded := strings.TrimSpace(deferred.Header().Get(headerRBACDeletedResourceIdentity))
		deferred.Header().Del(headerRBACDeletedResourceIdentity)
		if deferred.overflow {
			deny(c, http.StatusBadGateway, "Deletion response exceeded the safe ownership buffer")
			return
		}
		if !creationResponseSucceeded(deferred.Status(), deferred.body.Bytes()) {
			_ = deferred.commitTo(original)
			return
		}
		identity, err := decodeDeletedResourceIdentity(encoded)
		if err != nil || identity.Type != expectedType || strings.TrimSpace(identity.ID) == "" {
			global.LOG.Errorf("successful %s deletion did not return a valid RBAC canonical identity, node=%d path=%s", expectedType, nodeID, c.Request.URL.Path)
			deny(c, http.StatusInternalServerError, "Resource was deleted but ownership synchronization metadata was missing; administrator repair is required")
			return
		}
		if err := global.DB.Where("node_id = ? AND resource_type = ? AND resource_id = ?", nodeID, identity.Type, identity.ID).
			Delete(&model.AccessProjectResource{}).Error; err != nil {
			global.LOG.Errorf("successful %s deletion could not remove RBAC ownership node=%d id=%s: %v", expectedType, nodeID, identity.ID, err)
			deny(c, http.StatusInternalServerError, "Resource was deleted but project ownership cleanup failed; administrator repair is required")
			return
		}
		deferred.Header().Del(headerRBACDeletedResourceIdentity)
		if err := deferred.commitTo(original); err != nil {
			global.LOG.Errorf("flush committed resource deletion response: %v", err)
		}
	}
}

func deletionResourceType(path, method string) (string, bool) {
	if method != http.MethodPost { return "", false }
	switch path {
	case "/api/v2/websites/del":
		return "website", true
	case "/api/v2/runtimes/del":
		return "runtime", true
	case "/api/v2/databases/del", "/api/v2/databases/pg/del", "/api/v2/databases/mongodb/del":
		return "database", true
	default:
		return "", false
	}
}

func decodeDeletedResourceIdentity(encoded string) (deletedResourceIdentity, error) {
	var identity deletedResourceIdentity
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil { return identity, err }
	if err := json.Unmarshal(raw, &identity); err != nil { return identity, err }
	identity.Type = strings.TrimSpace(identity.Type)
	identity.ID = strings.TrimSpace(identity.ID)
	return identity, nil
}
