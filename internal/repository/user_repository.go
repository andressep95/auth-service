package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/domain"
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	GetByEmailAndApp(ctx context.Context, email string, appID uuid.UUID) (*domain.User, error)
	GetByVerificationToken(ctx context.Context, token string) (*domain.User, error)
	GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateLastLogin(ctx context.Context, id uuid.UUID) error
	ResetFailedLogins(ctx context.Context, id uuid.UUID) error
	IncrementFailedLogins(ctx context.Context, id uuid.UUID) error
	GetUserRoles(ctx context.Context, userID, appID uuid.UUID) ([]string, error)
	GetUserRolesAllApps(ctx context.Context, userID uuid.UUID) ([]string, error)
	List(ctx context.Context, limit, offset int, search string) ([]*domain.User, int, error)
	SuperAdminExists(ctx context.Context) (bool, error)
	AssignRole(ctx context.Context, userID, roleID uuid.UUID) error
}
