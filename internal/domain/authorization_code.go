package domain

import (
	"time"

	"github.com/google/uuid"
)

// AuthorizationCode represents an OAuth2 authorization code
// Implements Authorization Code Flow from RFC 6749
type AuthorizationCode struct {
	ID                    uuid.UUID  `json:"id" db:"id"`
	CodeHash              string     `json:"-" db:"code_hash"`                              // SHA-256 hash of the code
	AppID                 uuid.UUID  `json:"app_id" db:"app_id"`                            // Application that requested the code
	UserID                uuid.UUID  `json:"user_id" db:"user_id"`                          // User who authorized
	RedirectURI           string     `json:"redirect_uri" db:"redirect_uri"`                // Must match the URI used in /oauth/token
	Scope                 *string    `json:"scope,omitempty" db:"scope"`                    // Requested scopes (space-separated)
	State                 *string    `json:"state,omitempty" db:"state"`                    // Client state for CSRF protection
	CodeChallenge         *string    `json:"code_challenge,omitempty" db:"code_challenge"` // PKCE code challenge
	CodeChallengeMethod   *string    `json:"code_challenge_method,omitempty" db:"code_challenge_method"`
	Used                  bool       `json:"used" db:"used"`                // Whether the code has been exchanged for tokens
	ExpiresAt             time.Time  `json:"expires_at" db:"expires_at"`    // Typically 10 minutes from creation
	CreatedAt             time.Time  `json:"created_at" db:"created_at"`
}

// IsExpired checks if the authorization code has expired
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// IsValid checks if the code is still valid (not used and not expired)
func (ac *AuthorizationCode) IsValid() bool {
	return !ac.Used && !ac.IsExpired()
}
