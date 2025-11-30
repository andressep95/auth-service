package domain

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

type Claims struct {
	jwt.RegisteredClaims
	UserID      uuid.UUID `json:"uid"`
	Email       string    `json:"email"`
	Roles       []string  `json:"roles,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
	AppID       uuid.UUID `json:"app_id,omitempty"`
	TokenType   string    `json:"type"`
}
