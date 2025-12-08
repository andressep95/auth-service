package domain

import (
	"time"

	"github.com/google/uuid"
)

// Session represents an active user session with refresh token
// It stores the hashed refresh token and session metadata
type Session struct {
	ID               uuid.UUID `json:"id" db:"id"`
	UserID           uuid.UUID `json:"user_id" db:"user_id"`
	AppID            uuid.UUID `json:"app_id" db:"app_id"`
	RefreshTokenHash string    `json:"-" db:"refresh_token_hash"` // SHA-256 hash, never expose
	UserAgent        *string   `json:"user_agent,omitempty" db:"user_agent"`
	IPAddress        *string   `json:"ip_address,omitempty" db:"ip_address"`
	ExpiresAt        time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
}
