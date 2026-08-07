package service

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/global"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var accessUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{2,127}$`)

type AccessService struct{}

type IAccessService interface {
	ListUsers() ([]dto.AccessUserInfo, error)
	CreateUser(req dto.AccessUserCreate) error
	UpdateUser(req dto.AccessUserUpdate) error
	UpdateUserStatus(req dto.AccessUserStatusUpdate) error
	ResetUserPassword(req dto.AccessUserPasswordReset) error
	ReplaceUserBindings(req dto.AccessUserBindingsUpdate) error
	ListRoles() ([]dto.AccessRoleInfo, error)
	ListProjects() ([]dto.AccessProjectInfo, error)
	CreateProject(req dto.AccessProjectCreate) error
	UpdateProject(req dto.AccessProjectUpdate) error
	ReplaceProjectResources(req dto.AccessProjectResourcesUpdate) error
}

func NewIAccessService() IAccessService { return &AccessService{} }

func (s *AccessService) ListUsers() ([]dto.AccessUserInfo, error) {
	var users []model.AccessUser
	if err := global.DB.Order("username ASC").Find(&users).Error; err != nil {
		return nil, err
	}
	type bindingRow struct {
		ID, UserID, RoleID, NodeID                      uint
		RoleKey, RoleName, ScopeType, ScopeID, ResourceType string
	}
	var rows []bindingRow
	if err := global.DB.Table("rbac_role_bindings AS b").
		Select("b.id, b.user_id, b.role_id, b.node_id, r.key AS role_key, r.name AS role_name, b.scope_type, b.scope_id, b.resource_type").
		Joins("JOIN rbac_roles r ON r.id = b.role_id").
		Order("r.sort ASC, b.scope_type ASC, b.scope_id ASC, b.node_id ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	byUser := make(map[uint][]dto.AccessBindingInfo)
	for _, row := range rows {
		byUser[row.UserID] = append(byUser[row.UserID], dto.AccessBindingInfo{
			ID: row.ID, RoleID: row.RoleID, RoleKey: row.RoleKey, RoleName: row.RoleName,
			ScopeType: row.ScopeType, ScopeID: row.ScopeID, ResourceType: row.ResourceType, NodeID: row.NodeID,
		})
	}
	result := make([]dto.AccessUserInfo, 0, len(users))
	for _, user := range users {
		result = append(result, dto.AccessUserInfo{
			ID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Email: user.Email,
			Status: user.Status, AuthSource: user.AuthSource, RequireMFA: user.RequireMFA,
			MFAEnabled: user.MFAEnabled, LastLoginAt: user.LastLoginAt, CreatedAt: user.CreatedAt,
			Bindings: byUser[user.ID],
		})
	}
	return result, nil
}

func (s *AccessService) CreateUser(req dto.AccessUserCreate) error {
	username := strings.TrimSpace(req.Username)
	if !accessUsernamePattern.MatchString(username) {
		return errors.New("username contains unsupported characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil { return err }
	return global.DB.Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&model.AccessUser{}).Where("username = ?", username).Count(&count).Error; err != nil { return err }
		if count != 0 { return errors.New("username already exists") }
		bindings, err := validateBindings(tx, req.Bindings)
		if err != nil { return err }
		now := time.Now()
		user := model.AccessUser{Username: username, DisplayName: strings.TrimSpace(req.DisplayName), Email: strings.TrimSpace(req.Email), PasswordHash: string(hash), Status: model.AccessUserStatusActive, AuthSource: "local", RequireMFA: req.RequireMFA, PasswordChangedAt: &now}
		if user.DisplayName == "" { user.DisplayName = username }
		if err := tx.Create(&user).Error; err != nil { return err }
		for _, binding := range bindings {
			binding.UserID = user.ID
			if err := tx.Create(&binding).Error; err != nil { return err }
		}
		return nil
	})
}

func (s *AccessService) UpdateUser(req dto.AccessUserUpdate) error {
	var user model.AccessUser
	if err := global.DB.First(&user, req.ID).Error; err != nil { return err }
	return global.DB.Model(&user).Updates(map[string]any{"display_name": strings.TrimSpace(req.DisplayName), "email": strings.TrimSpace(req.Email), "require_mfa": req.RequireMFA}).Error
}

func (s *AccessService) UpdateUserStatus(req dto.AccessUserStatusUpdate) error {
	var user model.AccessUser
	if err := global.DB.First(&user, req.ID).Error; err != nil { return err }
	if req.Status == model.AccessUserStatusDisabled {
		last, err := isLastActiveGlobalAdministrator(global.DB, user.ID)
		if err != nil { return err }
		if last { return errors.New("the last active global administrator cannot be disabled") }
	}
	if err := global.DB.Model(&user).Update("status", req.Status).Error; err != nil { return err }
	if req.Status == model.AccessUserStatusDisabled { _ = global.SESSION.DeleteByID(strconv.FormatUint(uint64(user.ID), 10)) }
	return nil
}

func (s *AccessService) ResetUserPassword(req dto.AccessUserPasswordReset) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil { return err }
	now := time.Now()
	result := global.DB.Model(&model.AccessUser{}).Where("id = ?", req.ID).Updates(map[string]any{"password_hash": string(hash), "password_changed_at": &now})
	if result.Error != nil { return result.Error }
	if result.RowsAffected == 0 { return gorm.ErrRecordNotFound }
	_ = global.SESSION.DeleteByID(strconv.FormatUint(uint64(req.ID), 10))
	return nil
}

func (s *AccessService) ReplaceUserBindings(req dto.AccessUserBindingsUpdate) error {
	return global.DB.Transaction(func(tx *gorm.DB) error {
		var user model.AccessUser
		if err := tx.First(&user, req.ID).Error; err != nil { return err }
		bindings, err := validateBindings(tx, req.Bindings)
		if err != nil { return err }
		proposedGlobalAdmin := false
		for _, binding := range bindings {
			var role model.AccessRole
			if err := tx.First(&role, binding.RoleID).Error; err != nil { return err }
			if role.Key == rbac.RoleAdministrator && binding.ScopeType == model.AccessScopeGlobal { proposedGlobalAdmin = true }
		}
		if !proposedGlobalAdmin {
			last, err := isLastActiveGlobalAdministrator(tx, user.ID)
			if err != nil { return err }
			if last { return errors.New("the last active global administrator must keep the administrator role") }
		}
		if err := tx.Where("user_id = ?", user.ID).Delete(&model.AccessRoleBinding{}).Error; err != nil { return err }
		for _, binding := range bindings {
			binding.UserID = user.ID
			if err := tx.Create(&binding).Error; err != nil { return err }
		}
		_ = global.SESSION.DeleteByID(strconv.FormatUint(uint64(user.ID), 10))
		return nil
	})
}

func (s *AccessService) ListRoles() ([]dto.AccessRoleInfo, error) {
	var roles []model.AccessRole
	if err := global.DB.Order("sort ASC").Find(&roles).Error; err != nil { return nil, err }
	result := make([]dto.AccessRoleInfo, 0, len(roles))
	for _, role := range roles {
		var permissions []model.AccessPermission
		if err := global.DB.Table("rbac_permissions AS p").Select("p.*").Joins("JOIN rbac_role_permissions rp ON rp.permission_id = p.id").Where("rp.role_id = ?", role.ID).Order("p.resource_type ASC, p.feature ASC, p.action ASC").Scan(&permissions).Error; err != nil { return nil, err }
		item := dto.AccessRoleInfo{ID: role.ID, Key: role.Key, Name: role.Name, Description: role.Description, IsSystem: role.IsSystem, Sort: role.Sort}
		for _, permission := range permissions {
			item.Permissions = append(item.Permissions, dto.AccessPermissionInfo{Code: permission.Code, ResourceType: permission.ResourceType, Feature: permission.Feature, Action: permission.Action, RiskLevel: permission.RiskLevel, Description: permission.Description})
		}
		result = append(result, item)
	}
	return result, nil
}

func (s *AccessService) ListProjects() ([]dto.AccessProjectInfo, error) {
	var projects []model.AccessProject
	if err := global.DB.Order("name ASC").Find(&projects).Error; err != nil { return nil, err }
	result := make([]dto.AccessProjectInfo, 0, len(projects))
	for _, project := range projects {
		item := dto.AccessProjectInfo{ID: project.ID, Name: project.Name, Slug: project.Slug, Description: project.Description, RootPath: project.RootPath, Status: project.Status, CreatedAt: project.CreatedAt}
		var resources []model.AccessProjectResource
		if err := global.DB.Where("project_id = ?", project.ID).Order("node_id ASC, resource_type ASC, resource_id ASC").Find(&resources).Error; err != nil { return nil, err }
		for _, resource := range resources {
			item.Resources = append(item.Resources, dto.AccessProjectResourceInput{NodeID: resource.NodeID, ResourceType: resource.ResourceType, ResourceID: resource.ResourceID})
		}
		result = append(result, item)
	}
	return result, nil
}

func (s *AccessService) CreateProject(req dto.AccessProjectCreate) error {
	project := model.AccessProject{Name: strings.TrimSpace(req.Name), Slug: strings.ToLower(strings.TrimSpace(req.Slug)), Description: strings.TrimSpace(req.Description), Status: "active"}
	return global.DB.Create(&project).Error
}

func (s *AccessService) UpdateProject(req dto.AccessProjectUpdate) error {
	return global.DB.Model(&model.AccessProject{}).Where("id = ?", req.ID).Updates(map[string]any{"name": strings.TrimSpace(req.Name), "slug": strings.ToLower(strings.TrimSpace(req.Slug)), "description": strings.TrimSpace(req.Description), "status": req.Status}).Error
}

func (s *AccessService) ReplaceProjectResources(req dto.AccessProjectResourcesUpdate) error {
	return global.DB.Transaction(func(tx *gorm.DB) error {
		var project model.AccessProject
		if err := tx.First(&project, req.ID).Error; err != nil { return err }
		seen := make(map[string]struct{})
		normalized := make([]model.AccessProjectResource, 0, len(req.Resources))
		for _, input := range req.Resources {
			resourceType := strings.TrimSpace(input.ResourceType)
			resourceID := strings.TrimSpace(input.ResourceID)
			if resourceType == "" || resourceID == "" { return errors.New("project resource type and id are required") }
			if input.NodeID > 0 {
				var count int64
				if err := tx.Model(&model.AccessNodeScope{}).Where("id = ? AND status = ?", input.NodeID, model.AccessUserStatusActive).Count(&count).Error; err != nil || count == 0 {
					return fmt.Errorf("project resource references unknown or disabled node %d", input.NodeID)
				}
			}
			key := fmt.Sprintf("%d:%s:%s", input.NodeID, resourceType, resourceID)
			if _, exists := seen[key]; exists { continue }
			seen[key] = struct{}{}
			var owner model.AccessProjectResource
			err := tx.Where("node_id = ? AND resource_type = ? AND resource_id = ? AND project_id <> ?", input.NodeID, resourceType, resourceID, req.ID).First(&owner).Error
			if err == nil { return fmt.Errorf("resource %s is already owned by project %d", key, owner.ProjectID) }
			if !errors.Is(err, gorm.ErrRecordNotFound) { return err }
			normalized = append(normalized, model.AccessProjectResource{ProjectID: req.ID, NodeID: input.NodeID, ResourceType: resourceType, ResourceID: resourceID})
		}
		if err := tx.Where("project_id = ?", req.ID).Delete(&model.AccessProjectResource{}).Error; err != nil { return err }
		for _, resource := range normalized {
			if err := tx.Create(&resource).Error; err != nil { return err }
		}
		return nil
	})
}

func validateBindings(tx *gorm.DB, inputs []dto.AccessBindingInput) ([]model.AccessRoleBinding, error) {
	result := make([]model.AccessRoleBinding, 0, len(inputs))
	seen := make(map[string]struct{})
	for _, input := range inputs {
		var role model.AccessRole
		if err := tx.Where("key = ?", input.RoleKey).First(&role).Error; err != nil { return nil, fmt.Errorf("role %s does not exist: %w", input.RoleKey, err) }
		scopeType := strings.TrimSpace(input.ScopeType)
		scopeID := strings.TrimSpace(input.ScopeID)
		resourceType := strings.TrimSpace(input.ResourceType)
		if err := validateRoleScope(tx, role.Key, scopeType, scopeID, resourceType, input.NodeID); err != nil { return nil, err }
		key := fmt.Sprintf("%d:%s:%s:%s:%d", role.ID, scopeType, scopeID, resourceType, input.NodeID)
		if _, exists := seen[key]; exists { continue }
		seen[key] = struct{}{}
		result = append(result, model.AccessRoleBinding{RoleID: role.ID, ScopeType: scopeType, ScopeID: scopeID, ResourceType: resourceType, NodeID: input.NodeID})
	}
	return result, nil
}

func validateRoleScope(tx *gorm.DB, roleKey, scopeType, scopeID, resourceType string, nodeID uint) error {
	allowed := map[string]map[string]bool{
		rbac.RoleAdministrator: {model.AccessScopeGlobal: true},
		rbac.RoleDeveloper: {model.AccessScopeProject: true, model.AccessScopeResource: true},
		rbac.RoleSecurityAdvisor: {model.AccessScopeGlobal: true, model.AccessScopeNode: true, model.AccessScopeProject: true, model.AccessScopeResource: true},
		rbac.RoleUser: {model.AccessScopeProject: true, model.AccessScopeResource: true},
		rbac.RoleVisitor: {model.AccessScopeProject: true, model.AccessScopeResource: true},
	}
	roleScopes, ok := allowed[roleKey]
	if !ok || !roleScopes[scopeType] { return fmt.Errorf("role %s cannot be assigned at %s scope", roleKey, scopeType) }
	switch scopeType {
	case model.AccessScopeGlobal:
		if scopeID != "*" || resourceType != "" || nodeID != 0 { return errors.New("global scope requires scopeId='*', nodeId=0 and no resourceType") }
	case model.AccessScopeNode:
		parsed, err := strconv.ParseUint(scopeID, 10, 64)
		if err != nil || resourceType != "" || nodeID != 0 { return errors.New("node scope requires a numeric scopeId, nodeId=0 and no resourceType") }
		if parsed > 0 {
			var count int64
			if err := tx.Model(&model.AccessNodeScope{}).Where("id = ? AND status = ?", uint(parsed), model.AccessUserStatusActive).Count(&count).Error; err != nil || count == 0 { return errors.New("node scope references an unknown or disabled node") }
		}
	case model.AccessScopeProject:
		projectID, err := strconv.ParseUint(scopeID, 10, 64)
		if err != nil || projectID == 0 || resourceType != "" || nodeID != 0 { return errors.New("project scope requires a numeric project scopeId, nodeId=0 and no resourceType") }
		var count int64
		if err := tx.Model(&model.AccessProject{}).Where("id = ?", uint(projectID)).Count(&count).Error; err != nil || count == 0 { return errors.New("project scope references an unknown project") }
	case model.AccessScopeResource:
		if scopeID == "" || resourceType == "" { return errors.New("resource scope requires scopeId and resourceType") }
		if nodeID > 0 {
			var count int64
			if err := tx.Model(&model.AccessNodeScope{}).Where("id = ? AND status = ?", nodeID, model.AccessUserStatusActive).Count(&count).Error; err != nil || count == 0 { return errors.New("resource scope references an unknown or disabled node") }
		}
	default:
		return errors.New("unsupported scope type")
	}
	return nil
}

func isLastActiveGlobalAdministrator(tx *gorm.DB, targetUserID uint) (bool, error) {
	var targetCount int64
	if err := tx.Table("rbac_role_bindings AS b").Joins("JOIN rbac_roles r ON r.id = b.role_id").Where("b.user_id = ? AND r.key = ? AND b.scope_type = ? AND b.scope_id = ?", targetUserID, rbac.RoleAdministrator, model.AccessScopeGlobal, "*").Count(&targetCount).Error; err != nil { return false, err }
	if targetCount == 0 { return false, nil }
	var adminIDs []uint
	if err := tx.Table("rbac_role_bindings AS b").Distinct("b.user_id").Joins("JOIN rbac_roles r ON r.id = b.role_id").Joins("JOIN rbac_users u ON u.id = b.user_id").Where("r.key = ? AND b.scope_type = ? AND b.scope_id = ? AND u.status = ?", rbac.RoleAdministrator, model.AccessScopeGlobal, "*", model.AccessUserStatusActive).Pluck("b.user_id", &adminIDs).Error; err != nil { return false, err }
	sort.Slice(adminIDs, func(i, j int) bool { return adminIDs[i] < adminIDs[j] })
	return len(adminIDs) == 1 && adminIDs[0] == targetUserID, nil
}
