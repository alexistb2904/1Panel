package rbac

import (
	"errors"
	"fmt"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/utils/encrypt"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// MigrateAndSeed creates the community access-control schema and installs the
// stable permission/role catalog. It is intentionally independent from the
// proprietary enterprise provider.
func MigrateAndSeed(tx *gorm.DB) error {
	if err := tx.AutoMigrate(
		&model.AccessUser{},
		&model.AccessRole{},
		&model.AccessPermission{},
		&model.AccessRolePermission{},
		&model.AccessRoleBinding{},
		&model.AccessProject{},
		&model.AccessProjectResource{},
	); err != nil {
		return fmt.Errorf("migrate community RBAC schema: %w", err)
	}

	permissions, err := seedPermissions(tx)
	if err != nil {
		return err
	}
	roles, err := seedRoles(tx, permissions)
	if err != nil {
		return err
	}
	if err := bootstrapLegacyAdministrator(tx, roles[RoleAdministrator]); err != nil {
		return err
	}
	return nil
}

func seedPermissions(tx *gorm.DB) (map[string]model.AccessPermission, error) {
	result := make(map[string]model.AccessPermission, len(PermissionCatalog))
	for _, definition := range PermissionCatalog {
		var item model.AccessPermission
		err := tx.Where("code = ?", definition.Code).First(&item).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			item = model.AccessPermission{
				Code:         definition.Code,
				ResourceType: definition.ResourceType,
				Feature:      definition.Feature,
				Action:       definition.Action,
				RiskLevel:    definition.RiskLevel,
				Description:  definition.Description,
			}
			if err := tx.Create(&item).Error; err != nil {
				return nil, fmt.Errorf("create permission %s: %w", definition.Code, err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("load permission %s: %w", definition.Code, err)
		} else {
			updates := map[string]any{
				"resource_type": definition.ResourceType,
				"feature":       definition.Feature,
				"action":        definition.Action,
				"risk_level":    definition.RiskLevel,
				"description":   definition.Description,
			}
			if err := tx.Model(&item).Updates(updates).Error; err != nil {
				return nil, fmt.Errorf("update permission %s: %w", definition.Code, err)
			}
		}
		result[definition.Code] = item
	}
	return result, nil
}

func seedRoles(tx *gorm.DB, permissions map[string]model.AccessPermission) (map[string]model.AccessRole, error) {
	result := make(map[string]model.AccessRole, len(DefaultRoleDefinitions))
	for _, definition := range DefaultRoleDefinitions {
		var role model.AccessRole
		err := tx.Where("key = ?", definition.Key).First(&role).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			role = model.AccessRole{
				Key:         definition.Key,
				Name:        definition.Name,
				Description: definition.Description,
				IsSystem:    true,
				Sort:        definition.Sort,
			}
			if err := tx.Create(&role).Error; err != nil {
				return nil, fmt.Errorf("create role %s: %w", definition.Key, err)
			}
		} else if err != nil {
			return nil, fmt.Errorf("load role %s: %w", definition.Key, err)
		} else {
			if err := tx.Model(&role).Updates(map[string]any{
				"name":        definition.Name,
				"description": definition.Description,
				"is_system":   true,
				"sort":        definition.Sort,
			}).Error; err != nil {
				return nil, fmt.Errorf("update role %s: %w", definition.Key, err)
			}
		}

		// Built-in roles are policy templates. Keep their default permission set
		// deterministic; future custom roles can be added without being touched.
		if err := tx.Where("role_id = ?", role.ID).Delete(&model.AccessRolePermission{}).Error; err != nil {
			return nil, fmt.Errorf("reset permissions for role %s: %w", definition.Key, err)
		}
		for _, code := range definition.Permissions {
			permission, ok := permissions[code]
			if !ok {
				return nil, fmt.Errorf("role %s references unknown permission %s", definition.Key, code)
			}
			link := model.AccessRolePermission{RoleID: role.ID, PermissionID: permission.ID}
			if err := tx.Create(&link).Error; err != nil {
				return nil, fmt.Errorf("grant %s to role %s: %w", code, definition.Key, err)
			}
		}
		result[definition.Key] = role
	}
	return result, nil
}

func bootstrapLegacyAdministrator(tx *gorm.DB, administrator model.AccessRole) error {
	if administrator.ID == 0 {
		return errors.New("administrator role was not seeded")
	}

	var existingGlobalAdmins int64
	if err := tx.Model(&model.AccessRoleBinding{}).
		Where("role_id = ? AND scope_type = ? AND scope_id = ?", administrator.ID, model.AccessScopeGlobal, "*").
		Count(&existingGlobalAdmins).Error; err != nil {
		return fmt.Errorf("count administrator bindings: %w", err)
	}
	if existingGlobalAdmins > 0 {
		return nil
	}

	var usernameSetting model.Setting
	if err := tx.Where("key = ?", "UserName").First(&usernameSetting).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("load legacy username: %w", err)
	}

	var user model.AccessUser
	err := tx.Where("username = ?", usernameSetting.Value).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		var passwordSetting model.Setting
		if err := tx.Where("key = ?", "Password").First(&passwordSetting).Error; err != nil {
			return fmt.Errorf("load legacy administrator password: %w", err)
		}
		plainPassword, err := encrypt.StringDecrypt(passwordSetting.Value)
		if err != nil {
			return fmt.Errorf("decrypt legacy administrator password: %w", err)
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("hash legacy administrator password: %w", err)
		}
		now := time.Now()
		user = model.AccessUser{
			Username:          usernameSetting.Value,
			DisplayName:       usernameSetting.Value,
			PasswordHash:      string(hash),
			Status:            model.AccessUserStatusActive,
			AuthSource:        "local",
			PasswordChangedAt: &now,
		}
		if err := tx.Create(&user).Error; err != nil {
			return fmt.Errorf("create bootstrap administrator: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("load bootstrap administrator: %w", err)
	}

	binding := model.AccessRoleBinding{
		UserID:       user.ID,
		RoleID:       administrator.ID,
		ScopeType:    model.AccessScopeGlobal,
		ScopeID:      "*",
		ResourceType: "",
	}
	if err := tx.Create(&binding).Error; err != nil {
		return fmt.Errorf("bind bootstrap administrator role: %w", err)
	}
	return nil
}
