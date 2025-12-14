package domain

import (
	"time"

	"github.com/google/uuid"
)

// InvitationStatus represents the status of a tenant invitation
type InvitationStatus string

const (
	InvitationStatusActive  InvitationStatus = "active"
	InvitationStatusExpired InvitationStatus = "expired"
	InvitationStatusRevoked InvitationStatus = "revoked"
)

// TenantInvitation represents an invitation to join a tenant
type TenantInvitation struct {
	ID          uuid.UUID        `json:"id" db:"id"`
	TenantID    uuid.UUID        `json:"tenant_id" db:"tenant_id"`
	TokenHash   string           `json:"-" db:"token_hash"` // SHA-256 hash, never expose
	CreatedBy   uuid.UUID        `json:"created_by" db:"created_by"`
	RoleID      *uuid.UUID       `json:"role_id,omitempty" db:"role_id"` // Optional role to assign
	MaxUses     *int             `json:"max_uses,omitempty" db:"max_uses"` // NULL = unlimited
	CurrentUses int              `json:"current_uses" db:"current_uses"`
	ExpiresAt   time.Time        `json:"expires_at" db:"expires_at"`
	Status      InvitationStatus `json:"status" db:"status"`
	CreatedAt   time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at" db:"updated_at"`
}

// IsValid checks if the invitation is still valid
func (i *TenantInvitation) IsValid() bool {
	if i.Status != InvitationStatusActive {
		return false
	}

	if time.Now().After(i.ExpiresAt) {
		return false
	}

	if i.MaxUses != nil && i.CurrentUses >= *i.MaxUses {
		return false
	}

	return true
}

// CanBeUsed checks if the invitation can be used one more time
func (i *TenantInvitation) CanBeUsed() bool {
	return i.IsValid()
}
