package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/1Panel-dev/1Panel/agent/global"
	"github.com/gin-gonic/gin"
)

const headerRBACDeletedResourceIdentity = "X-Panel-RBAC-Deleted-Resource-Identity"

type deletedResourceIdentity struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// RBACDeletionIdentity resolves the immutable authorization identity before a
// destructive handler removes the Agent-side row. Core consumes this response
// header only after a successful deletion and then removes the corresponding
// project ownership row. The value is base64url JSON to avoid delimiter/header
// injection ambiguity and is stripped by Core before the browser response.
func RBACDeletionIdentity() gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, ok := deletionIdentityForRequest(c)
		if ok {
			raw, err := json.Marshal(identity)
			if err == nil {
				c.Header(headerRBACDeletedResourceIdentity, base64.RawURLEncoding.EncodeToString(raw))
			}
		}
		c.Next()
	}
}

func deletionIdentityForRequest(c *gin.Context) (deletedResourceIdentity, bool) {
	path := c.Request.URL.Path
	body, payload, err := readRBACJSONBody(c)
	if err != nil { return deletedResourceIdentity{}, false }
	if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }

	switch path {
	case "/api/v2/websites/del":
		id := uintValue(payload["id"])
		if id == 0 { return deletedResourceIdentity{}, false }
		var website model.Website
		if err := global.DB.Select("id", "alias").First(&website, id).Error; err != nil { return deletedResourceIdentity{}, false }
		alias := strings.TrimSpace(website.Alias)
		if alias == "" { return deletedResourceIdentity{}, false }
		return deletedResourceIdentity{Type: "website", ID: "website:" + alias}, true

	case "/api/v2/runtimes/del":
		id := uintValue(payload["id"])
		if id == 0 { return deletedResourceIdentity{}, false }
		key, err := service.RuntimeKeyForID(id)
		if err != nil || strings.TrimSpace(key) == "" { return deletedResourceIdentity{}, false }
		return deletedResourceIdentity{Type: "runtime", ID: key}, true

	case "/api/v2/databases/del", "/api/v2/databases/pg/del", "/api/v2/databases/mongodb/del":
		keys, ok, err := databaseKeysForRequest(path, payload)
		if err != nil || !ok || len(keys) != 1 || strings.TrimSpace(keys[0]) == "" { return deletedResourceIdentity{}, false }
		return deletedResourceIdentity{Type: "database", ID: keys[0]}, true
	}
	return deletedResourceIdentity{}, false
}
