package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/domain"
)

type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error)
	GetByToken(ctx context.Context, tokenHash string) (*domain.Session, error)
	GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error)
	Update(ctx context.Context, session *domain.Session) error
	Delete(ctx context.Context, id uuid.UUID) error
	DeleteByToken(ctx context.Context, tokenHash string) error
	DeleteExpired(ctx context.Context) error
}
