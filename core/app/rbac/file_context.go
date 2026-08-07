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

func FileAuthorizationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Header.Del(HeaderRBACAllowedRoots)
		if !strings.HasPrefix(c.Request.URL.Path, "/api/v2/files") {
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
		evaluator := NewEvaluator(global.DB)
		admin, err := evaluator.Can(userID, "settings.manage", ResourceContext{})
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate file access")
			return
		}
		if admin {
			setAgentRBACHeaders(c, userID, "administrator", "file", ResourceFilter{All: true})
			c.Next()
			return
		}
		nodeID, _, err := ResolveRequestNodeID(c)
		if err != nil {
			deny(c, http.StatusPreconditionFailed, err.Error())
			return
		}
		permission, ok := filePermissionForRequest(c.Request.Method, c.Request.URL.Path)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "This File Manager operation is restricted to administrators")
			return
		}
		roots, err := evaluator.AccessibleProjectRoots(userID, permission, nodeID)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to resolve file project roots")
			return
		}
		encoded, err := encodeAllowedRoots(roots)
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to encode file project roots")
			return
		}
		c.Request.Header.Set(HeaderRBACPermission, permission)
		c.Request.Header.Set(HeaderRBACResourceType, "file")
		c.Request.Header.Set(HeaderRBACUserID, stringUint(userID))
		if len(roots) == 0 {
			c.Request.Header.Set(HeaderRBACMode, RBACModeNone)
		} else {
			c.Request.Header.Set(HeaderRBACMode, RBACModeIDs)
		}
		c.Request.Header.Set(HeaderRBACAllowedRoots, encoded)
		c.Request.Header.Del(HeaderRBACResourceIDs)
		c.Next()
	}
}

func stringUint(value uint) string { return strconvFormatUint(uint64(value)) }

var strconvFormatUint = func(value uint64) string {
	const digits = "0123456789"
	if value == 0 { return "0" }
	buf := make([]byte, 0, 20)
	for value > 0 { buf = append(buf, digits[value%10]); value /= 10 }
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 { buf[i], buf[j] = buf[j], buf[i] }
	return string(buf)
}

func encodeAllowedRoots(roots []string) (string, error) {
	data, err := json.Marshal(roots)
	if err != nil { return "", err }
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func filePermissionForRequest(method, fullPath string) (string, bool) {
	path := strings.TrimPrefix(fullPath, "/api/v2/files")
	if method == http.MethodGet {
		switch path {
		case "/download": return "website.files.read", true
		default: return "", false
		}
	}
	if method != http.MethodPost { return "", false }
	read := map[string]bool{
		"/search": true, "/ai-search": true, "/upload/search": true, "/tree": true,
		"/content": true, "/preview": true, "/remarks": true, "/check": true,
		"/batch/check": true, "/chunkdownload": true, "/size": true, "/depth/size": true,
	}
	write := map[string]bool{
		"": true, "/mode": true, "/owner": true, "/compress": true, "/decompress": true,
		"/save": true, "/upload": true, "/chunkupload": true, "/rename": true, "/wget": true,
		"/move": true, "/batch/role": true, "/remark": true, "/convert": true,
	}
	remove := map[string]bool{"/del": true, "/batch/del": true}
	if read[path] { return "website.files.read", true }
	if write[path] { return "website.files.write", true }
	if remove[path] { return "website.files.delete", true }
	return "", false
}
