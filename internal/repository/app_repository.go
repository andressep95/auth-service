package repository

import (
	"context"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/google/uuid"
)

type AppRepository interface {
	Create(ctx context.Context, app *domain.App) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.App, error)
	GetByClientID(ctx context.Context, clientID string) (*domain.App, error)
	List(ctx context.Context) ([]*domain.App, error)
	Update(ctx context.Context, app *domain.App) error
	Delete(ctx context.Context, id uuid.UUID) error
}
