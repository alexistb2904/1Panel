package auth

import (
	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/gin-gonic/gin"
)

// GetSafeCurrentUserInfo applies authorization-aware redaction to the current
// user profile. Global API credentials are platform secrets and must never be
// disclosed merely because a user can authenticate to the panel.
func GetSafeCurrentUserInfo(c *gin.Context) (*dto.CurrentUserInfo, error) {
	info, err := GetCurrentUserInfoForContext(c)
	if err != nil {
		return nil, err
	}
	user, err := currentAccessUser(c)
	if err != nil {
		return info, nil
	}
	info.ID = user.ID

	evaluator := rbac.NewEvaluator(global.DB)
	canViewSettings, err := evaluator.Can(user.ID, "settings.view", rbac.ResourceContext{})
	if err != nil {
		return nil, err
	}
	canManageSettings, err := evaluator.Can(user.ID, "settings.manage", rbac.ResourceContext{})
	if err != nil {
		return nil, err
	}

	if !canViewSettings {
		info.ApiInterfaceStatus = ""
		info.ApiKey = ""
		info.IpWhiteList = ""
		info.ApiTrustedProxies = ""
		info.ApiKeyValidityTime = 0
		return info, nil
	}
	if !canManageSettings {
		info.ApiKey = ""
	}
	return info, nil
}
