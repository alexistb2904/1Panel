package middleware

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

var scopedWebsiteAliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// StableWebsiteIdentityGuard guarantees that the human-readable alias used as
// Core's ownership key is exactly the alias the Agent persists. The legacy
// website service may transform Unicode aliases (for example via punycode), so
// scoped creation accepts only an already-canonical ASCII identifier instead of
// authorizing one identity and materializing another.
func StableWebsiteIdentityGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost || strings.TrimSuffix(c.Request.URL.Path, "/") != "/api/v2/websites" {
			c.Next()
			return
		}
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		if c.GetHeader(headerRBACMode) != rbacModeIDs {
			c.Next()
			return
		}
		body, payload, err := readRBACJSONBody(c)
		if err != nil {
			denyWebsiteAccess(c, "Unable to validate stable website identity")
			return
		}
		if body != nil { c.Request.Body = io.NopCloser(bytes.NewReader(body)) }
		alias := strings.TrimSpace(valueString(payload["alias"]))
		if !scopedWebsiteAliasPattern.MatchString(alias) {
			denyWebsiteAccess(c, "Scoped website aliases must be canonical ASCII identifiers using letters, digits, dot, underscore or hyphen")
			return
		}
		c.Next()
	}
}
