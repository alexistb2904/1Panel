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

// IdentityMiddleware resolves an authenticated 1Panel session to the community
// RBAC identity. It does not infer authorization from URLs; handlers must use
// RequireGlobal or Evaluator.Can with an explicit resource context.
func IdentityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		sessionUser, err := global.SESSION.Get(c)
		if err != nil {
			c.Next()
			return
		}

		accessUser, err := accessUserForSession(sessionUser)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) && sessionUser.ID == psession.SuperAdminSessionUserID {
				// Upgrade compatibility: legacy administrator sessions remain usable
				// until the RBAC bootstrap migration has completed.
				c.Next()
				return
			}
			deny(c, http.StatusUnauthorized, "RBAC identity is not available")
			return
		}
		if accessUser.Status != model.AccessUserStatusActive {
			_ = global.SESSION.DeleteByID(sessionUser.ID)
			deny(c, http.StatusUnauthorized, "User account is disabled")
			return
		}
		c.Set(GinContextAccessUserIDKey, accessUser.ID)
		c.Next()
	}
}

func CurrentUserID(c *gin.Context) (uint, bool) {
	value, exists := c.Get(GinContextAccessUserIDKey)
	if !exists {
		return 0, false
	}
	id, ok := value.(uint)
	return id, ok && id != 0
}

// RequireGlobal is intended for platform-level endpoints such as user/role
// administration. Project and resource endpoints must instead build an
// explicit ResourceContext and call Evaluator.Can.
func RequireGlobal(permissionCode string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, ok := CurrentUserID(c)
		if !ok {
			deny(c, http.StatusPreconditionFailed, "RBAC identity is required")
			return
		}
		allowed, err := NewEvaluator(global.DB).Can(userID, permissionCode, ResourceContext{})
		if err != nil {
			deny(c, http.StatusInternalServerError, "Unable to evaluate permission")
			return
		}
		if !allowed {
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
	if err != nil || id == 0 {
		return user, gorm.ErrRecordNotFound
	}
	err = global.DB.First(&user, uint(id)).Error
	return user, err
}

func deny(c *gin.Context, code int, message string) {
	c.JSON(http.StatusOK, gin.H{
		"code":    code,
		"message": message,
	})
	c.Abort()
}
