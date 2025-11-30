package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type RoleRepository struct {
	db *sqlx.DB
}

func NewRoleRepository(db *sqlx.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// Create creates a new role
func (r *RoleRepository) Create(ctx context.Context, role *domain.Role) error {
	query := `
		INSERT INTO roles (id, app_id, name, description, created_at, updated_at)
		VALUES (:id, :app_id, :name, :description, :created_at, :updated_at)
	`
	_, err := r.db.NamedExecContext(ctx, query, role)
	if err != nil {
		return fmt.Errorf("failed to create role: %w", err)
	}
	return nil
}

// GetByID retrieves a role by ID
func (r *RoleRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Role, error) {
	var role domain.Role
	query := `SELECT * FROM roles WHERE id = $1`

	err := r.db.GetContext(ctx, &role, query, id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return &role, nil
}

// GetByName retrieves a role by name and app
func (r *RoleRepository) GetByName(ctx context.Context, appID uuid.UUID, name string) (*domain.Role, error) {
	var role domain.Role
	query := `SELECT * FROM roles WHERE app_id = $1 AND name = $2`

	err := r.db.GetContext(ctx, &role, query, appID, name)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	return &role, nil
}

// GetByAppID retrieves all roles for an app
func (r *RoleRepository) GetByAppID(ctx context.Context, appID uuid.UUID) ([]*domain.Role, error) {
	var roles []*domain.Role
	query := `SELECT * FROM roles WHERE app_id = $1 ORDER BY name`

	err := r.db.SelectContext(ctx, &roles, query, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get roles: %w", err)
	}

	return roles, nil
}

// Update updates a role
func (r *RoleRepository) Update(ctx context.Context, role *domain.Role) error {
	query := `
		UPDATE roles
		SET name = :name, description = :description, updated_at = :updated_at
		WHERE id = :id
	`
	result, err := r.db.NamedExecContext(ctx, query, role)
	if err != nil {
		return fmt.Errorf("failed to update role: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// Delete deletes a role
func (r *RoleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM roles WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("role not found")
	}

	return nil
}

// AssignRoleToUser assigns a role to a user
func (r *RoleRepository) AssignRoleToUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id, role_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to assign role to user: %w", err)
	}
	return nil
}

// RemoveRoleFromUser removes a role from a user
func (r *RoleRepository) RemoveRoleFromUser(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2`

	result, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to remove role from user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user role assignment not found")
	}

	return nil
}

// GetUserRolesByApp retrieves all roles for a user in a specific app
func (r *RoleRepository) GetUserRolesByApp(ctx context.Context, userID, appID uuid.UUID) ([]*domain.Role, error) {
	var roles []*domain.Role
	query := `
		SELECT r.*
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.app_id = $2
		ORDER BY r.name
	`

	err := r.db.SelectContext(ctx, &roles, query, userID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return roles, nil
}

// GetUsersWithRole retrieves all user IDs that have a specific role
func (r *RoleRepository) GetUsersWithRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	var userIDs []uuid.UUID
	query := `SELECT user_id FROM user_roles WHERE role_id = $1`

	err := r.db.SelectContext(ctx, &userIDs, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get users with role: %w", err)
	}

	return userIDs, nil
}

// GetRolePermissions retrieves all permissions for a role
func (r *RoleRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*domain.Permission, error) {
	var permissions []*domain.Permission
	query := `
		SELECT p.*
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1
		ORDER BY p.resource, p.action
	`

	err := r.db.SelectContext(ctx, &permissions, query, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	return permissions, nil
}

// AssignPermissionToRole assigns a permission to a role
func (r *RoleRepository) AssignPermissionToRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `
		INSERT INTO role_permissions (role_id, permission_id, created_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (role_id, permission_id) DO NOTHING
	`
	_, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to assign permission to role: %w", err)
	}
	return nil
}

// RemovePermissionFromRole removes a permission from a role
func (r *RoleRepository) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uuid.UUID) error {
	query := `DELETE FROM role_permissions WHERE role_id = $1 AND permission_id = $2`

	result, err := r.db.ExecContext(ctx, query, roleID, permissionID)
	if err != nil {
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("role permission assignment not found")
	}

	return nil
}

// GetUserPermissions retrieves all permissions for a user in a specific app
func (r *RoleRepository) GetUserPermissions(ctx context.Context, userID, appID uuid.UUID) ([]*domain.Permission, error) {
	var permissions []*domain.Permission
	query := `
		SELECT DISTINCT p.*
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.id
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.app_id = $2
		ORDER BY p.resource, p.action
	`

	err := r.db.SelectContext(ctx, &permissions, query, userID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	return permissions, nil
}

// HasPermission checks if a user has a specific permission
func (r *RoleRepository) HasPermission(ctx context.Context, userID uuid.UUID, resource, action string) (bool, error) {
	var count int
	query := `
		SELECT COUNT(*)
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		INNER JOIN roles r ON rp.role_id = r.id
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND p.resource = $2 AND p.action = $3
	`

	err := r.db.GetContext(ctx, &count, query, userID, resource, action)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return count > 0, nil
}
