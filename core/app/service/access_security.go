package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/global"
	"gorm.io/gorm"
)

func (s *AccessService) ListNodes() ([]dto.AccessNodeInfo, error) {
	var rows []model.AccessNodeScope
	if err := global.DB.Order("name ASC").Find(&rows).Error; err != nil { return nil, err }
	items := make([]dto.AccessNodeInfo, 0, len(rows))
	for _, row := range rows { items = append(items, dto.AccessNodeInfo{ID: row.ID, ExternalKey: row.ExternalKey, Name: row.Name, Status: row.Status, CreatedAt: row.CreatedAt}) }
	return items, nil
}

func (s *AccessService) CreateNode(req dto.AccessNodeCreate) error {
	item := model.AccessNodeScope{ExternalKey: strings.TrimSpace(req.ExternalKey), Name: strings.TrimSpace(req.Name), Status: model.AccessUserStatusActive}
	return global.DB.Create(&item).Error
}

func (s *AccessService) UpdateNode(req dto.AccessNodeUpdate) error {
	return global.DB.Model(&model.AccessNodeScope{}).Where("id = ?", req.ID).Updates(map[string]any{"external_key": strings.TrimSpace(req.ExternalKey), "name": strings.TrimSpace(req.Name), "status": req.Status}).Error
}

func (s *AccessService) ListServiceAccounts() ([]dto.AccessServiceAccountInfo, error) {
	var credentials []model.AccessServiceCredential
	if err := global.DB.Order("name ASC").Find(&credentials).Error; err != nil { return nil, err }
	items := make([]dto.AccessServiceAccountInfo, 0, len(credentials))
	for _, credential := range credentials {
		bindings, err := loadAccessBindings(credential.UserID)
		if err != nil { return nil, err }
		items = append(items, dto.AccessServiceAccountInfo{ID: credential.ID, UserID: credential.UserID, Name: credential.Name, KeyID: credential.KeyID, IPWhiteList: credential.IPWhiteList, Status: credential.Status, ExpiresAt: credential.ExpiresAt, LastUsedAt: credential.LastUsedAt, CreatedAt: credential.CreatedAt, Bindings: bindings})
	}
	return items, nil
}

func (s *AccessService) CreateServiceAccount(req dto.AccessServiceAccountCreate) (dto.AccessServiceAccountToken, error) {
	var result dto.AccessServiceAccountToken
	keyID, secret, hash, err := newServiceCredentialSecret()
	if err != nil { return result, err }
	err = global.DB.Transaction(func(tx *gorm.DB) error {
		bindings, err := validateBindings(tx, req.Bindings)
		if err != nil { return err }
		if err := validateServiceAccountBindings(tx, bindings); err != nil { return err }
		user := model.AccessUser{Username: "svc-" + keyID, DisplayName: strings.TrimSpace(req.Name), PasswordHash: "!", Status: model.AccessUserStatusActive, AuthSource: "service_account"}
		if err := tx.Create(&user).Error; err != nil { return err }
		for _, binding := range bindings {
			binding.UserID = user.ID
			if err := tx.Create(&binding).Error; err != nil { return err }
		}
		credential := model.AccessServiceCredential{UserID: user.ID, Name: strings.TrimSpace(req.Name), KeyID: keyID, SecretHash: hash, IPWhiteList: strings.TrimSpace(req.IPWhiteList), Status: model.AccessUserStatusActive, ExpiresAt: req.ExpiresAt}
		if err := tx.Create(&credential).Error; err != nil { return err }
		result = dto.AccessServiceAccountToken{ID: credential.ID, KeyID: keyID, Token: "1ps_" + keyID + "_" + secret}
		return nil
	})
	return result, err
}

func (s *AccessService) UpdateServiceAccount(req dto.AccessServiceAccountUpdate) error {
	return global.DB.Transaction(func(tx *gorm.DB) error {
		var credential model.AccessServiceCredential
		if err := tx.First(&credential, req.ID).Error; err != nil { return err }
		bindings, err := validateBindings(tx, req.Bindings)
		if err != nil { return err }
		if err := validateServiceAccountBindings(tx, bindings); err != nil { return err }
		if err := tx.Model(&credential).Updates(map[string]any{"name": strings.TrimSpace(req.Name), "ip_white_list": strings.TrimSpace(req.IPWhiteList), "expires_at": req.ExpiresAt, "status": req.Status}).Error; err != nil { return err }
		if err := tx.Model(&model.AccessUser{}).Where("id = ?", credential.UserID).Updates(map[string]any{"display_name": strings.TrimSpace(req.Name), "status": req.Status}).Error; err != nil { return err }
		if err := tx.Where("user_id = ?", credential.UserID).Delete(&model.AccessRoleBinding{}).Error; err != nil { return err }
		for _, binding := range bindings {
			binding.UserID = credential.UserID
			if err := tx.Create(&binding).Error; err != nil { return err }
		}
		return nil
	})
}

func (s *AccessService) RotateServiceAccount(req dto.AccessServiceAccountRotate) (dto.AccessServiceAccountToken, error) {
	var result dto.AccessServiceAccountToken
	keyID, secret, hash, err := newServiceCredentialSecret()
	if err != nil { return result, err }
	var credential model.AccessServiceCredential
	if err := global.DB.First(&credential, req.ID).Error; err != nil { return result, err }
	if err := global.DB.Model(&credential).Updates(map[string]any{"key_id": keyID, "secret_hash": hash, "last_used_at": nil}).Error; err != nil { return result, err }
	return dto.AccessServiceAccountToken{ID: credential.ID, KeyID: keyID, Token: "1ps_" + keyID + "_" + secret}, nil
}

func (s *AccessService) SearchAudit(req dto.AccessAuditSearch) (int64, []dto.AccessAuditInfo, error) {
	db := global.DB.Model(&model.AccessAuditEvent{})
	if req.Decision != "" { db = db.Where("decision = ?", req.Decision) }
	if req.SubjectType != "" { db = db.Where("subject_type = ?", req.SubjectType) }
	if req.Action != "" { db = db.Where("action LIKE ?", "%"+req.Action+"%") }
	if req.ResourceType != "" { db = db.Where("resource_type = ?", req.ResourceType) }
	if req.Info != "" {
		like := "%" + req.Info + "%"
		db = db.Where("subject_name LIKE ? OR resource_id LIKE ? OR path LIKE ? OR reason LIKE ?", like, like, like, like)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil { return 0, nil, err }
	var rows []model.AccessAuditEvent
	if err := db.Order("id DESC").Limit(req.PageSize).Offset((req.Page - 1) * req.PageSize).Find(&rows).Error; err != nil { return 0, nil, err }
	items := make([]dto.AccessAuditInfo, 0, len(rows))
	for _, row := range rows {
		items = append(items, dto.AccessAuditInfo{ID: row.ID, SubjectType: row.SubjectType, SubjectID: row.SubjectID, SubjectName: row.SubjectName, Action: row.Action, Decision: row.Decision, ResourceType: row.ResourceType, ResourceID: row.ResourceID, NodeID: row.NodeID, ProjectID: row.ProjectID, Method: row.Method, Path: row.Path, RemoteIP: row.RemoteIP, Reason: row.Reason, Metadata: row.Metadata, CreatedAt: row.CreatedAt})
	}
	return total, items, nil
}

func loadAccessBindings(userID uint) ([]dto.AccessBindingInfo, error) {
	type row struct {
		ID, RoleID, NodeID uint
		RoleKey, RoleName, ScopeType, ScopeID, ResourceType string
	}
	var rows []row
	if err := global.DB.Table("rbac_role_bindings AS b").Select("b.id, b.role_id, b.node_id, r.key AS role_key, r.name AS role_name, b.scope_type, b.scope_id, b.resource_type").Joins("JOIN rbac_roles r ON r.id = b.role_id").Where("b.user_id = ?", userID).Order("r.sort ASC, b.node_id ASC").Scan(&rows).Error; err != nil { return nil, err }
	items := make([]dto.AccessBindingInfo, 0, len(rows))
	for _, item := range rows {
		items = append(items, dto.AccessBindingInfo{ID: item.ID, RoleID: item.RoleID, RoleKey: item.RoleKey, RoleName: item.RoleName, ScopeType: item.ScopeType, ScopeID: item.ScopeID, ResourceType: item.ResourceType, NodeID: item.NodeID})
	}
	return items, nil
}

func validateServiceAccountBindings(tx *gorm.DB, bindings []model.AccessRoleBinding) error {
	for _, binding := range bindings {
		var role model.AccessRole
		if err := tx.First(&role, binding.RoleID).Error; err != nil { return err }
		if role.Key == rbac.RoleAdministrator { return errors.New("service accounts cannot receive the Administrator role") }
	}
	return nil
}

func newServiceCredentialSecret() (string, string, string, error) {
	keyBytes := make([]byte, 8)
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil { return "", "", "", err }
	if _, err := rand.Read(secretBytes); err != nil { return "", "", "", err }
	keyID := hex.EncodeToString(keyBytes)
	secret := hex.EncodeToString(secretBytes)
	sum := sha256.Sum256([]byte(secret))
	return keyID, secret, hex.EncodeToString(sum[:]), nil
}
