package router

import (
	v2 "github.com/1Panel-dev/1Panel/core/app/api/v2"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/middleware"
	"github.com/gin-gonic/gin"
)

type AccessRouter struct{}

func (s *AccessRouter) InitRouter(Router *gin.RouterGroup) {
	base := Router.Group("access").Use(middleware.SessionAuth()).Use(middleware.PasswordExpired())
	api := v2.ApiGroupApp.BaseApi

	userRead := base.Group("users").Use(rbac.RequireGlobal("access.user.view"))
	userRead.GET("", api.ListAccessUsers)

	userManage := base.Group("users").Use(rbac.RequireGlobal("access.user.manage"))
	userManage.POST("", api.CreateAccessUser)
	userManage.POST("/update", api.UpdateAccessUser)
	userManage.POST("/status", api.UpdateAccessUserStatus)
	userManage.POST("/password", api.ResetAccessUserPassword)

	bindingManage := base.Group("users").Use(rbac.RequireGlobal("access.user.manage"), rbac.RequireGlobal("access.role.manage"))
	bindingManage.POST("/bindings", api.ReplaceAccessUserBindings)

	roleRead := base.Group("roles").Use(rbac.RequireGlobal("access.role.view"))
	roleRead.GET("", api.ListAccessRoles)

	projectRead := base.Group("projects").Use(rbac.RequireGlobal("project.view"))
	projectRead.GET("", api.ListAccessProjects)

	projectCreate := base.Group("projects").Use(rbac.RequireGlobal("project.create"))
	projectCreate.POST("", api.CreateAccessProject)

	projectUpdate := base.Group("projects").Use(rbac.RequireGlobal("project.update"))
	projectUpdate.POST("/update", api.UpdateAccessProject)

	projectResources := base.Group("projects").Use(rbac.RequireGlobal("project.resource.manage"))
	projectResources.POST("/resources", api.ReplaceAccessProjectResources)
}
