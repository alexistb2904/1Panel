package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/api/v2/helper"
	"github.com/1Panel-dev/1Panel/agent/app/dto/response"
	"github.com/1Panel-dev/1Panel/agent/app/service"
	"github.com/gin-gonic/gin"
)

// RuntimeRestrictedExecution exposes only runtime operations whose execution
// target is already a concrete project-owned runtime and whose payload cannot
// redefine host/container topology. Generic create/update/delete and specialized
// package/config/process controls remain Administrator-only: upstream performs
// some lifecycles asynchronously and RuntimeUpdate can replace image, codeDir,
// host volumes, ports, environment and extra-hosts in one request.
func RuntimeRestrictedExecution() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader(headerInternalRequest) == "1" || c.GetHeader(headerRBACMode) == rbacModeAll {
			c.Next()
			return
		}
		mode := c.GetHeader(headerRBACMode)
		if mode != rbacModeIDs && mode != rbacModeNone {
			c.Next()
			return
		}

		path := strings.TrimPrefix(c.Request.URL.Path, "/api/v2/runtimes")
		if c.Request.Method == http.MethodGet {
			if id, ok := scopedRuntimeDetailID(path); ok {
				data, err := service.NewRuntimeService().Get(id)
				if err != nil {
					helper.InternalServer(c, err)
					c.Abort()
					return
				}
				redactRuntimeDTOForRBAC(data)
				helper.SuccessWithData(c, data)
				c.Abort()
				return
			}
		}

		switch {
		case path == "" && c.Request.Method == http.MethodPost:
			denyRuntimeAccess(c, "Runtime creation is administrator-only until asynchronous task completion is bound to ownership activation")
			return
		case path == "/update" && c.Request.Method == http.MethodPost:
			denyRuntimeAccess(c, "Generic runtime mutation is administrator-only because it can redefine image, host paths, ports, environment and container topology")
			return
		case path == "/del" && c.Request.Method == http.MethodPost:
			denyRuntimeAccess(c, "Runtime deletion is administrator-only until asynchronous task completion is bound to ownership cleanup")
			return
		case path == "/node/modules" || path == "/node/modules/operate",
			strings.HasPrefix(path, "/php/extensions"),
			path == "/php/config" || path == "/php/update" || path == "/php/file" || path == "/php/fpm/config" || path == "/php/container/update",
			strings.HasPrefix(path, "/supervisor/process"):
			c.JSON(http.StatusOK, gin.H{
				"code":    http.StatusForbidden,
				"message": "This runtime package/config/process operation is administrator-only until its execution target is project-confined",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

func scopedRuntimeDetailID(path string) (uint, bool) {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" || strings.Contains(trimmed, "/") {
		return 0, false
	}
	id, err := strconv.ParseUint(trimmed, 10, 64)
	return uint(id), err == nil && id != 0
}

// redactRuntimeDTOForRBAC uses an explicit deny of every field that can carry
// environment values, form values, host filesystem topology, container
// identities or host-network overrides. runtime.view remains useful for
// operational status without becoming a secret/host-metadata capability.
func redactRuntimeDTOForRBAC(item *response.RuntimeDTO) {
	if item == nil {
		return
	}
	item.Params = map[string]interface{}{}
	item.AppParams = nil
	item.Environments = nil
	item.Volumes = nil
	item.ExtraHosts = nil
	item.CodeDir = ""
	item.Path = ""
	item.Container = ""
	item.Source = ""
}
