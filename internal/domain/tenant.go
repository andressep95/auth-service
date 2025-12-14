package domain

import (
	"time"

	"github.com/google/uuid"
)

// TenantType represents the type of tenant
type TenantType string

const (
	TenantTypePublic     TenantType = "public"
	TenantTypeWorkspace  TenantType = "workspace"
	TenantTypeEnterprise TenantType = "enterprise"
)

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusTrial     TenantStatus = "trial"
)

// Tenant represents a workspace/organization within an app
type Tenant struct {
	ID                 uuid.UUID    `json:"id" db:"id"`
	AppID              uuid.UUID    `json:"app_id" db:"app_id"`
	Name               string       `json:"name" db:"name"`
	Slug               string       `json:"slug" db:"slug"`
	Type               TenantType   `json:"type" db:"type"`
	OwnerID            *uuid.UUID   `json:"owner_id,omitempty" db:"owner_id"`
	MaxUsers           *int         `json:"max_users,omitempty" db:"max_users"`
	CurrentUsersCount  int          `json:"current_users_count" db:"current_users_count"`
	Status             TenantStatus `json:"status" db:"status"`
	Metadata           *string      `json:"metadata,omitempty" db:"metadata"` // JSONB as string
	CreatedAt          time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at" db:"updated_at"`
}

// PublicTenantID is the fixed UUID for the "public" tenant of the base app
var PublicTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
