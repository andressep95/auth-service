package repository

import (
	"context"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/google/uuid"
)

type AuthorizationCodeRepository interface {
	// Create creates a new authorization code
	Create(ctx context.Context, code *domain.AuthorizationCode) error

	// GetByCodeHash retrieves an authorization code by its hash
	GetByCodeHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error)

	// MarkAsUsed marks an authorization code as used
	MarkAsUsed(ctx context.Context, id uuid.UUID) error

	// DeleteExpired deletes all expired authorization codes
	DeleteExpired(ctx context.Context) error

	// DeleteByUserID deletes all authorization codes for a user (e.g., on logout)
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}
