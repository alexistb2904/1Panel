package rbac

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/global"
	"github.com/1Panel-dev/1Panel/core/init/session/psession"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const GinContextAccessUserIDKey = "rbac_access_user_id"

func IdentityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if _, ok := CurrentUserID(c); ok {
			c.Next()
			return
		}
		sessionUser, err := global.SESSION.Get(c)
		if err != nil {
			c.Next()
			return
		}
		accessUser, err := accessUserForSession(sessionUser)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) && sessionUser.ID == psession.SuperAdminSessionUserID {
				if !CommunityRBACEnabled() {
					c.Next()
					return
				}
				_ = global.SESSION.DeleteByID(sessionUser.ID)
				deny(c, http.StatusUnauthorized, "Legacy administrator sessions are invalid after the Community RBAC migration")
				return
			}
			deny(c, http.StatusUnauthorized, "RBAC identity is not available")
			return
		}
		if accessUser.Status != model.AccessUserStatusActive || accessUser.AuthSource == "service_account" {
			_ = global.SESSION.DeleteByID(sessionUser.ID)
			deny(c, http.StatusUnauthorized, "User account is disabled or non-interactive")
			return
		}
		c.Set(GinContextAccessUserIDKey, accessUser.ID)
		c.Set(GinContextRBACSubjectTypeKey, "user")
		c.Next()
	}
}

func CurrentUserID(c *gin.Context) (uint, bool) {
	value, exists := c.Get(GinContextAccessUserIDKey)
	if !exists { return 0, false }
	id, ok := value.(uint)
	return id, ok && id != 0
}

func RequireGlobal(permissionCode string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := CurrentUserID(c)
		if !ok {
			AuditDecision(c, 0, permissionCode, "deny", "global", "", 0, 0, "RBAC identity is required")
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required")
			return
		}
		allowed, err := NewEvaluator(global.DB).CanGlobal(userID, permissionCode)
		if err != nil {
			AuditDecision(c, userID, permissionCode, "deny", "global", "", 0, 0, "permission evaluation failed")
			deny(c, http.StatusInternalServerError, "Unable to evaluate permission")
			return
		}
		if !allowed {
			AuditDecision(c, userID, permissionCode, "deny", "global", "", 0, 0, "permission denied")
			deny(c, http.StatusPreconditionFailed, "Permission denied: "+permissionCode)
			return
		}
		c.Next()
	}
}

func accessUserForSession(sessionUser psession.SessionUser) (model.AccessUser, error) {
	var user model.AccessUser
	if sessionUser.ID == psession.SuperAdminSessionUserID {
		err := global.DB.Where("username = ?", sessionUser.Name).First(&user).Error
		return user, err
	}
	id, err := strconv.ParseUint(sessionUser.ID, 10, 64)
	if err != nil || id == 0 { return user, gorm.ErrRecordNotFound }
	err = global.DB.First(&user, uint(id)).Error
	return user, err
}

func deny(c *gin.Context, code int, message string) {
	if _, alreadyRecorded := c.Get(auditDenyRecordedKey); !alreadyRecorded {
		if userID, ok := CurrentUserID(c); ok {
			AuditDecision(c, userID, "request.denied", "deny", "request", c.Request.URL.Path, 0, 0, message)
		}
	}
	c.JSON(http.StatusOK, gin.H{"code": code, "message": message})
	c.Abort()
}
