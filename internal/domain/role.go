package domain

import "github.com/google/uuid"

type Role struct {
	ID          uuid.UUID `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	AppID       uuid.UUID `json:"app_id" db:"app_id"`
	CreatedAt   string    `json:"created_at" db:"created_at"`
	UpdatedAt   string    `json:"updated_at" db:"updated_at"`
}

type Permission struct {
	ID       uuid.UUID `json:"id" db:"id"`
	Name     string    `json:"name" db:"name"`
	Resource string    `json:"resource" db:"resource"`
	Action   string    `json:"action" db:"action"`
}

type App struct {
	ID             uuid.UUID `json:"id" db:"id"`
	Name           string    `json:"name" db:"name"`
	ClientID       string    `json:"client_id" db:"client_id"`
	ClientSecret   string    `json:"-" db:"client_secret_hash"`
	RedirectURIs   []string  `json:"redirect_uris" db:"redirect_uris"`
	AllowedScopes  []string  `json:"allowed_scopes" db:"allowed_scopes"`
	CreatedAt      string    `json:"created_at" db:"created_at"`
	UpdatedAt      string    `json:"updated_at" db:"updated_at"`
}
