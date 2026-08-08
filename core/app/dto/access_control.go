package dto

import "time"

type AccessBindingInput struct {
	RoleKey      string `json:"roleKey" validate:"required"`
	ScopeType    string `json:"scopeType" validate:"required,oneof=global node project"`
	ScopeID      string `json:"scopeId" validate:"required"`
	ResourceType string `json:"resourceType"`
	NodeID       uint   `json:"nodeId"`
}

type AccessUserCreate struct {
	Username    string               `json:"username" validate:"required,min=3,max=128"`
	DisplayName string               `json:"displayName" validate:"max=255"`
	Email       string               `json:"email" validate:"omitempty,email,max=254"`
	Password    string               `json:"password" validate:"required,min=12,max=256"`
	RequireMFA  bool                 `json:"requireMFA"`
	Bindings    []AccessBindingInput `json:"bindings" validate:"required,min=1,dive"`
}

type AccessUserUpdate struct {
	ID          uint   `json:"id" validate:"required"`
	DisplayName string `json:"displayName" validate:"max=255"`
	Email       string `json:"email" validate:"omitempty,email,max=254"`
	RequireMFA  bool   `json:"requireMFA"`
}

type AccessUserStatusUpdate struct {
	ID     uint   `json:"id" validate:"required"`
	Status string `json:"status" validate:"required,oneof=active disabled"`
}

type AccessUserPasswordReset struct {
	ID       uint   `json:"id" validate:"required"`
	Password string `json:"password" validate:"required,min=12,max=256"`
}

type AccessUserBindingsUpdate struct {
	ID       uint                 `json:"id" validate:"required"`
	Bindings []AccessBindingInput `json:"bindings" validate:"required,min=1,dive"`
}

type AccessBindingInfo struct {
	ID           uint   `json:"id"`
	RoleID       uint   `json:"roleId"`
	RoleKey      string `json:"roleKey"`
	RoleName     string `json:"roleName"`
	ScopeType    string `json:"scopeType"`
	ScopeID      string `json:"scopeId"`
	ResourceType string `json:"resourceType"`
	NodeID       uint   `json:"nodeId"`
}

type AccessUserInfo struct {
	ID          uint                `json:"id"`
	Username    string              `json:"username"`
	DisplayName string              `json:"displayName"`
	Email       string              `json:"email"`
	Status      string              `json:"status"`
	AuthSource  string              `json:"authSource"`
	RequireMFA  bool                `json:"requireMFA"`
	MFAEnabled  bool                `json:"mfaEnabled"`
	LastLoginAt *time.Time          `json:"lastLoginAt"`
	CreatedAt   time.Time           `json:"createdAt"`
	Bindings    []AccessBindingInfo `json:"bindings"`
}

type AccessPermissionInfo struct {
	Code         string `json:"code"`
	ResourceType string `json:"resourceType"`
	Feature      string `json:"feature"`
	Action       string `json:"action"`
	RiskLevel    string `json:"riskLevel"`
	Description  string `json:"description"`
}

type AccessRoleInfo struct {
	ID          uint                   `json:"id"`
	Key         string                 `json:"key"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	IsSystem    bool                   `json:"isSystem"`
	Sort        int                    `json:"sort"`
	Permissions []AccessPermissionInfo `json:"permissions"`
}

type AccessProjectCreate struct {
	Name        string `json:"name" validate:"required,min=2,max=255"`
	Slug        string `json:"slug" validate:"required,min=2,max=128"`
	Description string `json:"description" validate:"max=1024"`
	RootPath    string `json:"rootPath" validate:"max=2048"`
}

type AccessProjectUpdate struct {
	ID          uint   `json:"id" validate:"required"`
	Name        string `json:"name" validate:"required,min=2,max=255"`
	Slug        string `json:"slug" validate:"required,min=2,max=128"`
	Description string `json:"description" validate:"max=1024"`
	Status      string `json:"status" validate:"required,oneof=active archived"`
}

type AccessProjectResourceInput struct {
	NodeID       uint   `json:"nodeId"`
	ResourceType string `json:"resourceType" validate:"required"`
	ResourceID   string `json:"resourceId" validate:"required"`
}

type AccessProjectResourcesUpdate struct {
	ID        uint                         `json:"id" validate:"required"`
	Resources []AccessProjectResourceInput `json:"resources" validate:"dive"`
}

type AccessProjectInfo struct {
	ID          uint                         `json:"id"`
	Name        string                       `json:"name"`
	Slug        string                       `json:"slug"`
	Description string                       `json:"description"`
	RootPath    string                       `json:"rootPath"`
	Status      string                       `json:"status"`
	CreatedAt   time.Time                    `json:"createdAt"`
	Resources   []AccessProjectResourceInput `json:"resources"`
	Nodes       []AccessProjectNodeInfo       `json:"nodes"`
}
