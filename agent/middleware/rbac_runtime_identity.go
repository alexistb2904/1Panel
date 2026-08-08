package middleware

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/gin-gonic/gin"
)

// StableRuntimeIdentityGuard binds the mutable request fields used by the
// legacy RuntimeUpdate handler to the concrete Agent runtime row. Core scopes
// ownership by runtime:<name>; a caller must not be able to send the ID of
// runtime A together with the owned name/project boundary of runtime B.
func StableRuntimeIdentityGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost || c.Request.URL.Path != "/api/v2/runtimes/update" {
			c.Next()
			return
		}
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		mode := c.GetHeader(headerRBACMode)
		if mode != rbacModeIDs && mode != rbacModeNone {
			c.Next()
			return
		}
		body, payload, err := readRBACJSONBody(c)
		if err != nil {
			denyRuntimeAccess(c, "Unable to validate stable runtime identity")
			return
		}
		if body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}
		id := uintValue(payload["id"])
		if id == 0 {
			id = uintValue(payload["ID"])
		}
		name := strings.TrimSpace(valueString(payload["name"]))
		if id == 0 || name == "" {
			denyRuntimeAccess(c, "Scoped runtime update requires both runtime ID and canonical name")
			return
		}
		actualKey, err := service.RuntimeKeyForID(id)
		if err != nil {
			denyRuntimeAccess(c, "Runtime target could not be resolved")
			return
		}
		expectedKey := service.RuntimeResourceKey(name)
		if actualKey != expectedKey {
			denyRuntimeAccess(c, "Runtime ID and canonical name refer to different resources")
			return
		}
		c.Next()
	}
}
