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
	ID            uuid.UUID  `json:"id" db:"id"`
	Email         string     `json:"email" db:"email"`
	PasswordHash  string     `json:"-" db:"password_hash"`
	FirstName     string     `json:"first_name" db:"first_name"`
	LastName      string     `json:"last_name" db:"last_name"`
	Status        UserStatus `json:"status" db:"status"`
	EmailVerified bool       `json:"email_verified" db:"email_verified"`
	MFAEnabled    bool       `json:"mfa_enabled" db:"mfa_enabled"`
	MFASecret     *string    `json:"-" db:"mfa_secret"`
	FailedLogins  int        `json:"-" db:"failed_logins"`
	LockedUntil   *time.Time `json:"-" db:"locked_until"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
	LastLoginAt   *time.Time `json:"last_login_at" db:"last_login_at"`
}
