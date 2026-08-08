package dto

import "time"

type AccessNodeCreate struct {
	ExternalKey string `json:"externalKey" validate:"required,min=1,max=255"`
	Name        string `json:"name" validate:"required,min=1,max=255"`
}

type AccessNodeUpdate struct {
	ID          uint   `json:"id" validate:"required"`
	ExternalKey string `json:"externalKey" validate:"required,min=1,max=255"`
	Name        string `json:"name" validate:"required,min=1,max=255"`
	Status      string `json:"status" validate:"required,oneof=active disabled"`
}

type AccessNodeInfo struct {
	ID          uint      `json:"id"`
	ExternalKey string    `json:"externalKey"`
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
}

type AccessServiceAccountCreate struct {
	Name        string               `json:"name" validate:"required,min=2,max=255"`
	IPWhiteList string               `json:"ipWhiteList" validate:"max=4096"`
	ExpiresAt   *time.Time           `json:"expiresAt"`
	Bindings    []AccessBindingInput `json:"bindings" validate:"required,min=1,dive"`
}

type AccessServiceAccountUpdate struct {
	ID          uint                 `json:"id" validate:"required"`
	Name        string               `json:"name" validate:"required,min=2,max=255"`
	IPWhiteList string               `json:"ipWhiteList" validate:"max=4096"`
	ExpiresAt   *time.Time           `json:"expiresAt"`
	Status      string               `json:"status" validate:"required,oneof=active disabled"`
	Bindings    []AccessBindingInput `json:"bindings" validate:"required,min=1,dive"`
}

type AccessServiceAccountRotate struct {
	ID uint `json:"id" validate:"required"`
}

type AccessServiceAccountInfo struct {
	ID          uint                `json:"id"`
	UserID      uint                `json:"userId"`
	Name        string              `json:"name"`
	KeyID       string              `json:"keyId"`
	IPWhiteList string              `json:"ipWhiteList"`
	Status      string              `json:"status"`
	ExpiresAt   *time.Time          `json:"expiresAt"`
	LastUsedAt  *time.Time          `json:"lastUsedAt"`
	CreatedAt   time.Time           `json:"createdAt"`
	Bindings    []AccessBindingInfo `json:"bindings"`
}

type AccessServiceAccountToken struct {
	ID    uint   `json:"id"`
	KeyID string `json:"keyId"`
	Token string `json:"token"`
}

type AccessAuditSearch struct {
	PageInfo
	Decision     string `json:"decision" validate:"omitempty,oneof=allow deny"`
	SubjectType  string `json:"subjectType"`
	Action       string `json:"action"`
	ResourceType string `json:"resourceType"`
	Info         string `json:"info"`
}

type AccessAuditInfo struct {
	ID           uint      `json:"id"`
	SubjectType  string    `json:"subjectType"`
	SubjectID    uint      `json:"subjectId"`
	SubjectName  string    `json:"subjectName"`
	Action       string    `json:"action"`
	Decision     string    `json:"decision"`
	ResourceType string    `json:"resourceType"`
	ResourceID   string    `json:"resourceId"`
	NodeID       uint      `json:"nodeId"`
	ProjectID    uint      `json:"projectId"`
	Method       string    `json:"method"`
	Path         string    `json:"path"`
	RemoteIP     string    `json:"remoteIp"`
	Reason       string    `json:"reason"`
	Metadata     string    `json:"metadata"`
	CreatedAt    time.Time `json:"createdAt"`
}
