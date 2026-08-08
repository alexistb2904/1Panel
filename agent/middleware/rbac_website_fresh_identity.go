package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

// WebsiteFreshIdentityGuard prevents a newly owned website:<alias> capability
// from adopting filesystem state left behind by an older website with the same
// human-readable alias. Stable names are useful lookup identities, but they are
// not immutable object identities; stale directory reuse would otherwise turn
// delete/recreate into an unintended data-access grant.
func WebsiteFreshIdentityGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		if c.GetHeader(headerRBACMode) != rbacModeIDs || c.Request.Method != http.MethodPost || strings.TrimSuffix(c.Request.URL.Path, "/") != "/api/v2/websites" {
			c.Next()
			return
		}
		body, payload, err := readRBACJSONBody(c)
		if err != nil {
			denyWebsiteAccess(c, "Unable to validate website filesystem identity")
			return
		}
		if body != nil {
			c.Request.Body = io.NopCloser(bytes.NewReader(body))
		}
		alias := strings.TrimSpace(valueString(payload["alias"]))
		if err := validateFreshScopedWebsiteAlias(alias, "/www/sites"); err != nil {
			denyWebsiteAccess(c, err.Error())
			return
		}
		c.Next()
	}
}

func validateFreshScopedWebsiteAlias(alias, sitesRoot string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" || alias == "." || alias == ".." || !scopedWebsiteAliasPattern.MatchString(alias) {
		return errors.New("Scoped website alias must be a simple ASCII identifier without path separators")
	}
	root := filepath.Clean(sitesRoot)
	candidate := filepath.Clean(filepath.Join(root, alias))
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return errors.New("Scoped website alias escapes the managed sites directory")
	}
	if _, err := os.Lstat(candidate); err == nil {
		return errors.New("Scoped website creation refuses an alias with pre-existing filesystem state; an administrator must inspect or remove the stale directory first")
	} else if !os.IsNotExist(err) {
		return errors.New("Unable to prove that the scoped website filesystem identity is fresh")
	}
	return nil
}
