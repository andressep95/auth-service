package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/domain"
)

type InvitationRepository interface {
	Create(ctx context.Context, invitation *domain.TenantInvitation) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.TenantInvitation, error)
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.TenantInvitation, error)
	Update(ctx context.Context, invitation *domain.TenantInvitation) error
	IncrementUses(ctx context.Context, id uuid.UUID) error
	ListByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*domain.TenantInvitation, int, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
