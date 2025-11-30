package service

import (
	"context"
	"errors"
	"time"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/google/uuid"
)

var (
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleAlreadyExists = errors.New("role already exists")
	ErrPermissionDenied  = errors.New("permission denied")
	ErrCannotDeleteRole  = errors.New("cannot delete role with assigned users")
)

type RoleService struct {
	roleRepo repository.RoleRepository
	userRepo repository.UserRepository
}

func NewRoleService(roleRepo repository.RoleRepository, userRepo repository.UserRepository) *RoleService {
	return &RoleService{
		roleRepo: roleRepo,
		userRepo: userRepo,
	}
}

// CreateRole creates a new role
func (s *RoleService) CreateRole(ctx context.Context, appID uuid.UUID, name, description string) (*domain.Role, error) {
	// Check if role already exists
	existing, err := s.roleRepo.GetByName(ctx, appID, name)
	if err == nil && existing != nil {
		return nil, ErrRoleAlreadyExists
	}

	now := time.Now()
	role := &domain.Role{
		ID:          uuid.New(),
		AppID:       appID,
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err = s.roleRepo.Create(ctx, role); err != nil {
		return nil, err
	}

	return role, nil
}

// GetRole retrieves a role by ID
func (s *RoleService) GetRole(ctx context.Context, roleID uuid.UUID) (*domain.Role, error) {
	return s.roleRepo.GetByID(ctx, roleID)
}

// GetRolesByApp retrieves all roles for an app
func (s *RoleService) GetRolesByApp(ctx context.Context, appID uuid.UUID) ([]*domain.Role, error) {
	return s.roleRepo.GetByAppID(ctx, appID)
}

// UpdateRole updates a role
func (s *RoleService) UpdateRole(ctx context.Context, roleID uuid.UUID, name, description string) error {
	role, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		if err == ErrRoleNotFound {
			return ErrRoleNotFound
		}
		return err
	}

	role.Name = name
	role.Description = description
	role.UpdatedAt = time.Now()

	return s.roleRepo.Update(ctx, role)
}

// DeleteRole deletes a role
func (s *RoleService) DeleteRole(ctx context.Context, roleID uuid.UUID) error {
	// Check if any users have this role
	users, err := s.roleRepo.GetUsersWithRole(ctx, roleID)
	if err != nil {
		return err
	}

	if len(users) > 0 {
		return ErrCannotDeleteRole
	}

	return s.roleRepo.Delete(ctx, roleID)
}

// AssignRoleToUser assigns a role to a user
func (s *RoleService) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	// Verify user exists
	_, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify role exists
	_, err = s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return ErrRoleNotFound
	}

	return s.roleRepo.AssignRoleToUser(ctx, userID, roleID)
}

// RemoveRoleFromUser removes a role from a user
func (s *RoleService) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	return s.roleRepo.RemoveRoleFromUser(ctx, userID, roleID)
}

// GetUserRoles retrieves all roles for a user in an app
func (s *RoleService) GetUserRoles(ctx context.Context, userID, appID uuid.UUID) ([]*domain.Role, error) {
	return s.roleRepo.GetUserRolesByApp(ctx, userID, appID)
}

// GetRolePermissions retrieves all permissions for a role
func (s *RoleService) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error) {
	return s.roleRepo.GetRolePermissions(ctx, roleID)
}

// AssignPermissionToRole assigns a permission to a role
func (s *RoleService) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	// Verify role exists
	_, err := s.roleRepo.GetByID(ctx, roleID)
	if err != nil {
		return ErrRoleNotFound
	}

	return s.roleRepo.AssignPermissionToRole(ctx, roleID, permissionID)
}

// RemovePermissionFromRole removes a permission from a role
func (s *RoleService) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	return s.roleRepo.RemovePermissionFromRole(ctx, roleID, permissionID)
}

// GetUserPermissions retrieves all permissions for a user in an app
func (s *RoleService) GetUserPermissions(ctx context.Context, userID, appID uuid.UUID) ([]*domain.Permission, error) {
	return s.roleRepo.GetUserPermissions(ctx, userID, appID)
}

// HasPermission checks if a user has a specific permission
func (s *RoleService) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	return s.roleRepo.HasPermission(ctx, userID, resource, action)
}

// HasRole checks if a user has a specific role
func (s *RoleService) HasRole(ctx context.Context, userID uuid.UUID, roleName string) (bool, error) {
	// Get base app ID - using system default app
	baseAppID, err := uuid.Parse("00000000-0000-0000-0000-000000000000")
	if err != nil {
		return false, err
	}

	roles, err := s.roleRepo.GetUserRolesByApp(ctx, userID, baseAppID)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role.Name == roleName {
			return true, nil
		}
	}

	return false, nil
}
