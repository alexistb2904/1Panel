package model

import "time"

const (
	AccessUserStatusActive   = "active"
	AccessUserStatusDisabled = "disabled"

	AccessScopeGlobal   = "global"
	AccessScopeNode     = "node"
	AccessScopeProject  = "project"
	AccessScopeResource = "resource"
)

// AccessUser is a local 1Panel account used by the community RBAC layer.
// Authentication-specific secrets stay on the user record while authorization
// is expressed through AccessRoleBinding.
type AccessUser struct {
	BaseModel
	Username          string     `gorm:"size:128;not null;uniqueIndex" json:"username"`
	DisplayName       string     `gorm:"size:255" json:"displayName"`
	Email             string     `gorm:"size:254;index" json:"email"`
	PasswordHash      string     `gorm:"size:255;not null" json:"-"`
	Status            string     `gorm:"size:32;not null;index" json:"status"`
	AuthSource        string     `gorm:"size:32;not null;default:local" json:"authSource"`
	RequireMFA        bool       `gorm:"not null;default:false" json:"requireMFA"`
	MFAEnabled        bool       `gorm:"not null;default:false" json:"mfaEnabled"`
	MFASecret         string     `gorm:"type:text" json:"-"`
	LastLoginAt       *time.Time `json:"lastLoginAt"`
	PasswordChangedAt *time.Time `json:"passwordChangedAt"`
}

func (AccessUser) TableName() string { return "rbac_users" }

type AccessRole struct {
	BaseModel
	Key         string `gorm:"size:64;not null;uniqueIndex" json:"key"`
	Name        string `gorm:"size:128;not null" json:"name"`
	Description string `gorm:"size:512" json:"description"`
	IsSystem    bool   `gorm:"not null;default:false" json:"isSystem"`
	Sort        int    `gorm:"not null;default:0" json:"sort"`
}

func (AccessRole) TableName() string { return "rbac_roles" }

type AccessPermission struct {
	BaseModel
	Code         string `gorm:"size:128;not null;uniqueIndex" json:"code"`
	ResourceType string `gorm:"size:64;not null;index" json:"resourceType"`
	Feature      string `gorm:"size:64;not null" json:"feature"`
	Action       string `gorm:"size:64;not null" json:"action"`
	RiskLevel    string `gorm:"size:16;not null;index" json:"riskLevel"`
	Description  string `gorm:"size:512" json:"description"`
}

func (AccessPermission) TableName() string { return "rbac_permissions" }

type AccessRolePermission struct {
	RoleID       uint `gorm:"primaryKey;autoIncrement:false" json:"roleId"`
	PermissionID uint `gorm:"primaryKey;autoIncrement:false" json:"permissionId"`
}

func (AccessRolePermission) TableName() string { return "rbac_role_permissions" }

// AccessRoleBinding assigns a role to a user at one scope. Global bindings use
// ScopeID="*". Resource bindings additionally set ResourceType.
type AccessRoleBinding struct {
	BaseModel
	UserID       uint   `gorm:"not null;index;uniqueIndex:idx_rbac_binding,priority:1" json:"userId"`
	RoleID       uint   `gorm:"not null;index;uniqueIndex:idx_rbac_binding,priority:2" json:"roleId"`
	ScopeType    string `gorm:"size:32;not null;index;uniqueIndex:idx_rbac_binding,priority:3" json:"scopeType"`
	ScopeID      string `gorm:"size:128;not null;uniqueIndex:idx_rbac_binding,priority:4" json:"scopeId"`
	ResourceType string `gorm:"size:64;not null;default:'';uniqueIndex:idx_rbac_binding,priority:5" json:"resourceType"`
}

func (AccessRoleBinding) TableName() string { return "rbac_role_bindings" }

// AccessProject is an authorization boundary grouping resources that belong to
// the same internal application/product. It intentionally does not model a
// reseller/customer hierarchy.
type AccessProject struct {
	BaseModel
	Name        string `gorm:"size:255;not null" json:"name"`
	Slug        string `gorm:"size:128;not null;uniqueIndex" json:"slug"`
	Description string `gorm:"size:1024" json:"description"`
	Status      string `gorm:"size:32;not null;default:active;index" json:"status"`
}

func (AccessProject) TableName() string { return "rbac_projects" }

type AccessProjectResource struct {
	BaseModel
	ProjectID    uint   `gorm:"not null;index;uniqueIndex:idx_rbac_project_resource,priority:1" json:"projectId"`
	NodeID       uint   `gorm:"not null;default:0;index;uniqueIndex:idx_rbac_project_resource,priority:2" json:"nodeId"`
	ResourceType string `gorm:"size:64;not null;index;uniqueIndex:idx_rbac_project_resource,priority:3" json:"resourceType"`
	ResourceID   string `gorm:"size:128;not null;uniqueIndex:idx_rbac_project_resource,priority:4" json:"resourceId"`
}

func (AccessProjectResource) TableName() string { return "rbac_project_resources" }
