package repository

import (
	"context"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/google/uuid"
)

type RoleRepository interface {
	// Role CRUD
	Create(ctx context.Context, role *domain.Role) error
	GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error)
	GetByName(ctx context.Context, appID uuid.UUID, name string) (*domain.Role, error)
	GetByAppID(ctx context.Context, appID uuid.UUID) ([]*domain.Role, error)
	Update(ctx context.Context, role *domain.Role) error
	Delete(ctx context.Context, id uuid.UUID) error

	// User-Role assignments
	AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error
	RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error
	GetUserRolesByApp(ctx context.Context, userID, appID uuid.UUID) ([]*domain.Role, error)
	GetUsersWithRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error)

	// Permissions
	GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error)
	AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error
	GetUserPermissions(ctx context.Context, userID, appID uuid.UUID) ([]*domain.Permission, error)
	HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error)
}
