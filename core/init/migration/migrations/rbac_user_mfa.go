package migrations

import (
	"errors"
	"strconv"

	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/constant"
	"github.com/1Panel-dev/1Panel/core/utils/encrypt"
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// AddCommunityRBACUserMFAFields makes per-user MFA schema changes independently
// from the initial RBAC migration. It also preserves an existing Community
// administrator's MFA setup when upgrading from the legacy single-user model.
var AddCommunityRBACUserMFAFields = &gormigrate.Migration{
	ID: "20260807-add-community-rbac-user-mfa-fields",
	Migrate: func(tx *gorm.DB) error {
		if err := tx.AutoMigrate(&model.AccessUser{}); err != nil {
			return err
		}

		var username model.Setting
		if err := tx.Where("key = ?", "UserName").First(&username).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		var user model.AccessUser
		if err := tx.Where("username = ?", username.Value).First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return nil
			}
			return err
		}
		if user.MFAEnabled {
			return nil
		}

		var status, secret, interval model.Setting
		if err := tx.Where("key = ?", "MFAStatus").First(&status).Error; err != nil {
			return nil
		}
		if status.Value != constant.StatusEnable {
			return nil
		}
		if err := tx.Where("key = ?", "MFASecret").First(&secret).Error; err != nil || secret.Value == "" {
			return nil
		}
		mfaInterval := 30
		if err := tx.Where("key = ?", "MFAInterval").First(&interval).Error; err == nil {
			if parsed, parseErr := strconv.Atoi(interval.Value); parseErr == nil && parsed > 0 {
				mfaInterval = parsed
			}
		}
		encryptedSecret, err := encrypt.StringEncrypt(secret.Value)
		if err != nil {
			return err
		}
		return tx.Model(&user).Updates(map[string]any{
			"mfa_enabled":  true,
			"require_mfa":  true,
			"mfa_secret":   encryptedSecret,
			"mfa_interval": mfaInterval,
		}).Error
	},
}
