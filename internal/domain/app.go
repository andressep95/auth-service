package domain

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type App struct {
	ID               uuid.UUID `json:"id" db:"id"`
	Name             string    `json:"name" db:"name"`
	ClientID         string    `json:"client_id" db:"client_id"`
	ClientSecretHash string    `json:"-" db:"client_secret_hash"`
	Description      *string   `json:"description,omitempty" db:"description"`
	// OAuth
	RedirectURIs pq.StringArray `json:"redirect_uris" db:"redirect_uris"`
	WebOrigins   pq.StringArray `json:"web_origins" db:"web_origins"`
	// Branding
	LogoURL      *string   `json:"logo_url,omitempty" db:"logo_url"`
	PrimaryColor string    `json:"primary_color" db:"primary_color"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}
