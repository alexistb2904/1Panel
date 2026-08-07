package router

import (
	v2 "github.com/1Panel-dev/1Panel/core/app/api/v2"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/middleware"
	"github.com/gin-gonic/gin"
)

type AccessRouter struct{}

func (s *AccessRouter) InitRouter(Router *gin.RouterGroup) {
	base := Router.Group("access")
	base.Use(middleware.SessionAuth(), middleware.PasswordExpired())
	api := v2.ApiGroupApp.BaseApi

	userRead := base.Group("users")
	userRead.Use(rbac.RequireGlobal("access.user.view"))
	userRead.GET("", api.ListAccessUsers)

	userManage := base.Group("users")
	userManage.Use(rbac.RequireGlobal("access.user.manage"))
	userManage.POST("", api.CreateAccessUser)
	userManage.POST("/update", api.UpdateAccessUser)
	userManage.POST("/status", api.UpdateAccessUserStatus)
	userManage.POST("/password", api.ResetAccessUserPassword)

	bindingManage := base.Group("users")
	bindingManage.Use(rbac.RequireGlobal("access.user.manage"), rbac.RequireGlobal("access.role.manage"))
	bindingManage.POST("/bindings", api.ReplaceAccessUserBindings)

	roleRead := base.Group("roles")
	roleRead.Use(rbac.RequireGlobal("access.role.view"))
	roleRead.GET("", api.ListAccessRoles)

	projectRead := base.Group("projects")
	projectRead.Use(rbac.RequireGlobal("project.view"))
	projectRead.GET("", api.ListAccessProjects)

	projectCreate := base.Group("projects")
	projectCreate.Use(rbac.RequireGlobal("project.create"))
	projectCreate.POST("", api.CreateAccessProject)

	projectUpdate := base.Group("projects")
	projectUpdate.Use(rbac.RequireGlobal("project.update"))
	projectUpdate.POST("/update", api.UpdateAccessProject)

	projectResources := base.Group("projects")
	projectResources.Use(rbac.RequireGlobal("project.resource.manage"))
	projectResources.POST("/resources", api.ReplaceAccessProjectResources)
}
