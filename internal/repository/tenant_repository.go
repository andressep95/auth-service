package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/domain"
)

type TenantRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)
	GetBySlug(ctx context.Context, appID uuid.UUID, slug string) (*domain.Tenant, error)
	GetPublicTenant(ctx context.Context, appID uuid.UUID) (*domain.Tenant, error)
	Create(ctx context.Context, tenant *domain.Tenant) error
	Update(ctx context.Context, tenant *domain.Tenant) error
	List(ctx context.Context, appID uuid.UUID, limit, offset int) ([]*domain.Tenant, int, error)
}
