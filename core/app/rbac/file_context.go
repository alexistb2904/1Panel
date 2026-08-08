package rbac

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

const HeaderRBACAllowedRoots = "X-Panel-RBAC-Allowed-Roots"

func isPublicFileShareRBACBypass(path string) bool {
	switch path {
	case "/api/v2/files/share/info", "/api/v2/files/share/check", "/api/v2/files/share/download":
		return true
	default:
		return false
	}
}

func FileAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Header.Del(HeaderRBACAllowedRoots)
		if !strings.HasPrefix(c.Request.URL.Path, "/api/v2/files") {
			c.Next()
			return
		}
		// Public shares are capability URLs validated independently by Agent's
		// FileSharePublicAccess middleware and intentionally do not inherit the
		// interactive user's filesystem permissions.
		if isPublicFileShareRBACBypass(c.Request.URL.Path) {
			c.Next()
			return
		}
		if c.GetBool("API_AUTH") || c.GetBool("LOCAL_REQUEST") {
			setAgentRBACHeaders(c, 0, "platform.internal", "file", ResourceFilter{All: true})
			c.Next()
			return
		}
		userID, ok := CurrentUserID(c)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required for file access")
			return
		}
		admin, err := NewEvaluator(global.DB).CanGlobal(userID, "settings.manage")
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate file access")
			return
		}
		if admin {
			setAgentRBACHeaders(c, userID, "administrator", "file", ResourceFilter{All: true})
			c.Next()
			return
		}

		// Path-string validation cannot provide a hostile-tenant filesystem
		// boundary. A project workload can rename directories or swap a symlink
		// after validation and before a legacy handler opens the pathname. Until
		// the File Manager is implemented with directory FDs + openat2
		// RESOLVE_BENEATH/NO_SYMLINKS (and fd-relative rename/unlink), allowing
		// even read-only scoped access would overstate the isolation guarantee.
		// Fail closed rather than shipping a raceable sandbox.
		AuditDecision(c, userID, "file.scoped", "deny", "file", c.Request.URL.Path, 0, 0, "scoped File Manager requires fd-relative confinement")
		deny(c, http.StatusForbidden, "Scoped File Manager is disabled until fd-relative filesystem confinement is implemented")
	}
}

// The helpers below intentionally remain as reusable building blocks for the
// future fd-relative File Manager implementation and compatibility tests. They
// are not currently used as an authorization boundary for non-admin users.
func stringUint(value uint) string { return strconvFormatUint(uint64(value)) }

var strconvFormatUint = func(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for value > 0 {
		buf = append(buf, digits[value%10])
		value /= 10
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}

func encodeAllowedRoots(roots []string) (string, error) {
	data, err := json.Marshal(roots)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func filePermissionForRequest(method, fullPath string) (string, bool) {
	path := strings.TrimPrefix(fullPath, "/api/v2/files")
	if method == http.MethodGet {
		switch path {
		case "/download":
			return "website.files.read", true
		default:
			return "", false
		}
	}
	if method != http.MethodPost {
		return "", false
	}
	read := map[string]bool{
		"/search": true, "/ai-search": true, "/upload/search": true, "/tree": true,
		"/content": true, "/preview": true, "/remarks": true, "/check": true,
		"/batch/check": true, "/chunkdownload": true, "/size": true, "/depth/size": true,
	}
	write := map[string]bool{
		"": true, "/save": true, "/upload": true, "/chunkupload": true,
		"/rename": true, "/move": true, "/remark": true,
	}
	remove := map[string]bool{"/del": true, "/batch/del": true}
	if read[path] {
		return "website.files.read", true
	}
	if write[path] {
		return "website.files.write", true
	}
	if remove[path] {
		return "website.files.delete", true
	}
	return "", false
}
