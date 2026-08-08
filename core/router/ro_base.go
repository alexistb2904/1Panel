package router

import (
	v2 "github.com/1Panel-dev/1Panel/core/app/api/v2"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/middleware"
	"github.com/gin-gonic/gin"
)

type BaseRouter struct{}

func (s *BaseRouter) InitRouter(Router *gin.RouterGroup) {
	baseRouter := Router.Group("auth")
	authRouter := Router.Group("auth").
		Use(middleware.SessionAuth()).
		Use(middleware.PasswordExpired()).
		Use(rbac.RequireInteractiveUser())
	adminAuthRouter := Router.Group("auth").
		Use(middleware.SessionAuth()).
		Use(middleware.PasswordExpired()).
		Use(rbac.RequireGlobal("settings.manage"))
	baseApi := v2.ApiGroupApp.BaseApi
	{
		baseRouter.GET("/captcha", baseApi.Captcha)
		baseRouter.POST("/passkey/begin", rbac.DisableLegacyPasskeyLoginAfterRBAC(), baseApi.PasskeyBeginLogin)
		baseRouter.POST("/passkey/finish", rbac.DisableLegacyPasskeyLoginAfterRBAC(), baseApi.PasskeyFinishLogin)
		baseRouter.POST("/mfalogin", rbac.RequireCommunityMFASessionAfterRBAC(), baseApi.MFALogin)
		baseRouter.POST("/login", rbac.PreserveGlobalLanguageOnLogin(), rbac.RejectLegacyLoginAfterRBAC(), baseApi.Login)
		baseRouter.POST("/logout", baseApi.LogOut)
		baseRouter.GET("/setting", baseApi.GetLoginSetting)
		baseRouter.GET("/welcome", baseApi.GetWelcomePage)

		authRouter.POST("/mfa", baseApi.LoadMFA)
		authRouter.POST("/mfa/bind", baseApi.MFABind)
		authRouter.POST("/mfa/close", baseApi.MFAClose)

		adminAuthRouter.POST("/passkey/register/begin", rbac.DisableLegacyPasskeyLoginAfterRBAC(), baseApi.PasskeyRegisterBegin)
		adminAuthRouter.POST("/passkey/register/finish", rbac.DisableLegacyPasskeyLoginAfterRBAC(), baseApi.PasskeyRegisterFinish)
		adminAuthRouter.GET("/passkey/list", rbac.DisableLegacyPasskeyLoginAfterRBAC(), baseApi.PasskeyList)
		adminAuthRouter.POST("/passkey/del", rbac.DisableLegacyPasskeyLoginAfterRBAC(), baseApi.PasskeyDelete)

		adminAuthRouter.POST("/api/generate", baseApi.GenerateApiKey)
		adminAuthRouter.POST("/api/update", baseApi.UpdateApiConfig)

		authRouter.GET("/current", baseApi.GetCurrentUser)
		authRouter.POST("/current/update", rbac.ValidateCurrentUserUpdate(), baseApi.UpdateCurrentUser)
		authRouter.POST("/expired/reset", baseApi.ResetPassword)
	}
}
