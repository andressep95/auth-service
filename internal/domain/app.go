package domain

import (
	"time"

	"github.com/google/uuid"
)

type App struct {
	ID               uuid.UUID `json:"id" db:"id"`
	Name             string    `json:"name" db:"name"`
	ClientID         string    `json:"client_id" db:"client_id"`
	ClientSecretHash string    `json:"-" db:"client_secret_hash"`
	Description      string    `json:"description" db:"description"`
	RedirectURL      string    `json:"redirect_url" db:"redirect_url"`
	LogoURL          *string   `json:"logo_url,omitempty" db:"logo_url"`
	PrimaryColor     string    `json:"primary_color" db:"primary_color"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}
