package domain

import (
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusInactive UserStatus = "inactive"
	UserStatusLocked   UserStatus = "locked"
)

type User struct {
	ID                              uuid.UUID  `json:"id" db:"id"`
	AppID                           uuid.UUID  `json:"app_id" db:"app_id"`
	Email                           string     `json:"email" db:"email"`
	PasswordHash                    string     `json:"-" db:"password_hash"`
	FirstName                       string     `json:"first_name" db:"first_name"`
	LastName                        string     `json:"last_name" db:"last_name"`
	Status                          UserStatus `json:"status" db:"status"`
	EmailVerified                   bool       `json:"email_verified" db:"email_verified"`
	MFAEnabled                      bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret                       *string    `json:"-" db:"mfa_secret"`
	FailedLogins                    int        `json:"-" db:"failed_logins"`
	LockedUntil                     *time.Time `json:"-" db:"locked_until"`
	EmailVerificationToken          *string    `json:"-" db:"email_verification_token"`
	EmailVerificationTokenExpiresAt *time.Time `json:"-" db:"email_verification_token_expires_at"`
	PasswordResetToken              *string    `json:"-" db:"password_reset_token"`
	PasswordResetTokenExpiresAt     *time.Time `json:"-" db:"password_reset_token_expires_at"`
	Provider                        *string    `json:"provider,omitempty" db:"provider"`
	ProviderID                      *string    `json:"provider_id,omitempty" db:"provider_id"`
	IsSuperAdmin                    bool       `json:"is_super_admin" db:"is_super_admin"`
	CreatedAt                       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt                       time.Time  `json:"updated_at" db:"updated_at"`
	LastLoginAt                     *time.Time `json:"last_login_at" db:"last_login_at"`
}
