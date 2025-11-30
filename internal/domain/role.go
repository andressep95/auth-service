package domain

import (
	"time"

	"github.com/google/uuid"
)

// Role represents a role in the RBAC system
type Role struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name" validate:"required,min=2,max=100"`
	Description string    `json:"description" db:"description" validate:"max=500"`
	AppID       uuid.UUID `json:"app_id" db:"app_id" validate:"required"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// Permission represents a granular permission in the system
type Permission struct {
	ID       uuid.UUID `json:"id" db:"id"`
	Name     string    `json:"name" db:"name" validate:"required,min=2,max=100"`
	Resource string    `json:"resource" db:"resource" validate:"required,min=2,max=100"`
	Action   string    `json:"action" db:"action" validate:"required,min=2,max=50"`
}

// App represents an application registered in the auth system
type App struct {
	ID                uuid.UUID `json:"id" db:"id"`
	Name              string    `json:"name" db:"name" validate:"required,min=2,max=255"`
	ClientID          string    `json:"client_id" db:"client_id" validate:"required"`
	ClientSecretHash  string    `json:"-" db:"client_secret_hash"` // Never expose in JSON
	RedirectURIs      []string  `json:"redirect_uris" db:"redirect_uris"`
	AllowedScopes     []string  `json:"allowed_scopes" db:"allowed_scopes"`
	CreatedAt         time.Time `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time `json:"updated_at" db:"updated_at"`
}
