package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/google/uuid"
)

const (
	// AuthorizationCodeExpiry is the duration for which an authorization code is valid
	AuthorizationCodeExpiry = 10 * time.Minute

	// AuthorizationCodeLength is the length of the generated code in bytes (32 bytes = 256 bits)
	AuthorizationCodeLength = 32
)

type OAuthService struct {
	authCodeRepo repository.AuthorizationCodeRepository
	appRepo      repository.AppRepository
}

func NewOAuthService(
	authCodeRepo repository.AuthorizationCodeRepository,
	appRepo repository.AppRepository,
) *OAuthService {
	return &OAuthService{
		authCodeRepo: authCodeRepo,
		appRepo:      appRepo,
	}
}

// GenerateAuthorizationCode generates a new authorization code for a user
func (s *OAuthService) GenerateAuthorizationCode(
	ctx context.Context,
	appID uuid.UUID,
	userID uuid.UUID,
	redirectURI string,
	state *string,
	scope *string,
) (string, error) {
	// Generate random code
	code, err := generateRandomCode(AuthorizationCodeLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	// Hash the code for storage
	codeHash := hashCode(code)

	// Create authorization code entity
	authCode := &domain.AuthorizationCode{
		ID:          uuid.New(),
		CodeHash:    codeHash,
		AppID:       appID,
		UserID:      userID,
		RedirectURI: redirectURI,
		State:       state,
		Scope:       scope,
		Used:        false,
		ExpiresAt:   time.Now().Add(AuthorizationCodeExpiry),
	}

	// Store in database
	if err := s.authCodeRepo.Create(ctx, authCode); err != nil {
		return "", fmt.Errorf("failed to store authorization code: %w", err)
	}

	return code, nil
}

// ValidateRedirectURI validates if the provided redirect URI is in the app's whitelist
func (s *OAuthService) ValidateRedirectURI(ctx context.Context, appID uuid.UUID, redirectURI string) error {
	// Get app details
	app, err := s.appRepo.GetByID(ctx, appID)
	if err != nil {
		return fmt.Errorf("failed to get app: %w", err)
	}

	// Parse the redirect URI
	parsedURI, err := url.Parse(redirectURI)
	if err != nil {
		return errors.New("invalid redirect URI format")
	}

	// Check if redirect_uris is empty (allow any for development)
	if len(app.RedirectURIs) == 0 {
		return errors.New("no redirect URIs configured for this app")
	}

	// Validate against whitelist
	for _, allowedURI := range app.RedirectURIs {
		parsedAllowed, err := url.Parse(allowedURI)
		if err != nil {
			continue
		}

		// Match scheme, host, and path exactly
		if parsedURI.Scheme == parsedAllowed.Scheme &&
			parsedURI.Host == parsedAllowed.Host &&
			parsedURI.Path == parsedAllowed.Path {
			return nil
		}
	}

	return errors.New("redirect URI not whitelisted for this app")
}

// ExchangeCodeForTokens validates and exchanges an authorization code for access and refresh tokens
func (s *OAuthService) ExchangeCodeForTokens(
	ctx context.Context,
	code string,
	redirectURI string,
) (*domain.AuthorizationCode, error) {
	// Hash the code
	codeHash := hashCode(code)

	// Get authorization code from database
	authCode, err := s.authCodeRepo.GetByCodeHash(ctx, codeHash)
	if err != nil {
		return nil, errors.New("invalid authorization code")
	}

	// Validate code is not expired
	if authCode.IsExpired() {
		return nil, errors.New("authorization code has expired")
	}

	// Validate code has not been used
	if authCode.Used {
		return nil, errors.New("authorization code has already been used")
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect URI mismatch")
	}

	// Mark code as used
	if err := s.authCodeRepo.MarkAsUsed(ctx, authCode.ID); err != nil {
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}

	return authCode, nil
}

// generateRandomCode generates a cryptographically secure random code
func generateRandomCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// hashCode generates a SHA-256 hash of the code
func hashCode(code string) string {
	hash := sha256.Sum256([]byte(code))
	return base64.URLEncoding.EncodeToString(hash[:])
}
