package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
)

type userRepository struct {
	db *sqlx.DB
}

// NewUserRepository creates a new PostgreSQL user repository
func NewUserRepository(db *sqlx.DB) repository.UserRepository {
	return &userRepository{db: db}
}

// Create inserts a new user into the database
func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (
			id, app_id, tenant_id, email, password_hash, first_name, last_name,
			status, email_verified, mfa_enabled, mfa_secret,
			failed_logins, locked_until,
			email_verification_token, email_verification_token_expires_at,
			password_reset_token, password_reset_token_expires_at,
			provider, provider_id, is_super_admin,
			created_at, updated_at, last_login_at
		) VALUES (
			:id, :app_id, :tenant_id, :email, :password_hash, :first_name, :last_name,
			:status, :email_verified, :mfa_enabled, :mfa_secret,
			:failed_logins, :locked_until,
			:email_verification_token, :email_verification_token_expires_at,
			:password_reset_token, :password_reset_token_expires_at,
			:provider, :provider_id, :is_super_admin,
			:created_at, :updated_at, :last_login_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by their ID
func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, app_id, tenant_id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   provider, provider_id, is_super_admin,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE id = $1`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get user by id: %w", err)
	}

	return &user, nil
}

// GetByEmail retrieves a user by their email address
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	log.Printf("[REPO] GetByEmail called for: %s", email)

	query := `
		SELECT id, app_id, tenant_id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   provider, provider_id, is_super_admin,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE email = $1`

	log.Printf("[REPO] Executing query: %s with email=%s", query, email)

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[REPO] No rows found for email: %s", email)
			return nil, fmt.Errorf("user not found: %w", err)
		}
		log.Printf("[REPO] Database error for email %s: %v", email, err)
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	log.Printf("[REPO] User found: ID=%s, Email=%s, AppID=%s", user.ID, user.Email, user.AppID)
	return &user, nil
}

// GetByEmailAndApp retrieves a user by their email address and app ID (multi-tenant)
// Note: This method now returns the first user found with this email in the app
// For tenant-specific lookups, use GetByEmailAppAndTenant instead
func (r *userRepository) GetByEmailAndApp(ctx context.Context, email string, appID uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, app_id, tenant_id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   provider, provider_id, is_super_admin,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE email = $1 AND app_id = $2
		LIMIT 1`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, email, appID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get user by email and app: %w", err)
	}

	return &user, nil
}

// GetByEmailAppAndTenant retrieves a user by their email, app ID and tenant ID (full multi-tenant)
func (r *userRepository) GetByEmailAppAndTenant(ctx context.Context, email string, appID, tenantID uuid.UUID) (*domain.User, error) {
	log.Printf("[REPO] GetByEmailAppAndTenant called for: email=%s, app_id=%s, tenant_id=%s", email, appID, tenantID)

	query := `
		SELECT id, app_id, tenant_id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   provider, provider_id, is_super_admin,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE email = $1 AND app_id = $2 AND tenant_id = $3`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, email, appID, tenantID)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("[REPO] No user found for email=%s, app_id=%s, tenant_id=%s", email, appID, tenantID)
			return nil, fmt.Errorf("user not found: %w", err)
		}
		log.Printf("[REPO] Database error: %v", err)
		return nil, fmt.Errorf("failed to get user by email, app and tenant: %w", err)
	}

	log.Printf("[REPO] User found: ID=%s, Email=%s, TenantID=%s", user.ID, user.Email, user.TenantID)
	return &user, nil
}

// Update updates an existing user in the database
func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE users
		SET email = :email,
			password_hash = :password_hash,
			first_name = :first_name,
			last_name = :last_name,
			status = :status,
			email_verified = :email_verified,
			mfa_enabled = :mfa_enabled,
			mfa_secret = :mfa_secret,
			failed_logins = :failed_logins,
			locked_until = :locked_until,
			email_verification_token = :email_verification_token,
			email_verification_token_expires_at = :email_verification_token_expires_at,
			password_reset_token = :password_reset_token,
			password_reset_token_expires_at = :password_reset_token_expires_at,
			provider = :provider,
			provider_id = :provider_id,
			is_super_admin = :is_super_admin,
			updated_at = :updated_at,
			last_login_at = :last_login_at
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// Delete removes a user from the database
func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// UpdateLastLogin updates the last login timestamp for a user
func (r *userRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET last_login_at = $1,
			updated_at = $2
		WHERE id = $3`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// ResetFailedLogins resets the failed login counter for a user
func (r *userRepository) ResetFailedLogins(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET failed_logins = 0,
			locked_until = NULL,
			updated_at = $1
		WHERE id = $2`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to reset failed logins: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// IncrementFailedLogins increments the failed login counter for a user
func (r *userRepository) IncrementFailedLogins(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE users
		SET failed_logins = failed_logins + 1,
			updated_at = $1
		WHERE id = $2`

	result, err := r.db.ExecContext(ctx, query, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to increment failed logins: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("user not found")
	}

	return nil
}

// GetUserRoles retrieves all roles for a user in a specific application
func (r *userRepository) GetUserRoles(ctx context.Context, userID, appID uuid.UUID) ([]string, error) {
	query := `
		SELECT r.name
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND r.app_id = $2`

	var roles []string
	err := r.db.SelectContext(ctx, &roles, query, userID, appID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return roles, nil
}

// GetUserRolesAllApps retrieves all roles for a user across all applications
func (r *userRepository) GetUserRolesAllApps(ctx context.Context, userID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT r.name
		FROM roles r
		INNER JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1
		ORDER BY r.name`

	var roles []string
	err := r.db.SelectContext(ctx, &roles, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	return roles, nil
}

// GetByVerificationToken retrieves a user by their email verification token
func (r *userRepository) GetByVerificationToken(ctx context.Context, token string) (*domain.User, error) {
	query := `
		SELECT id, app_id, tenant_id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   provider, provider_id, is_super_admin,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE email_verification_token = $1`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, token)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get user by verification token: %w", err)
	}

	return &user, nil
}

// GetByPasswordResetToken retrieves a user by their password reset token
func (r *userRepository) GetByPasswordResetToken(ctx context.Context, token string) (*domain.User, error) {
	query := `
		SELECT id, app_id, tenant_id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   provider, provider_id, is_super_admin,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE password_reset_token = $1`

	var user domain.User
	err := r.db.GetContext(ctx, &user, query, token)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get user by password reset token: %w", err)
	}

	return &user, nil
}

// List retrieves users with pagination and optional search
func (r *userRepository) List(ctx context.Context, limit, offset int, search string) ([]*domain.User, int, error) {
	var users []*domain.User
	var total int

	// Count total
	countQuery := `SELECT COUNT(*) FROM users WHERE 1=1`
	if search != "" {
		countQuery += ` AND (email ILIKE '%' || $1 || '%' OR first_name ILIKE '%' || $1 || '%' OR last_name ILIKE '%' || $1 || '%')`
		err := r.db.GetContext(ctx, &total, countQuery, search)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to count users: %w", err)
		}
	} else {
		err := r.db.GetContext(ctx, &total, countQuery)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to count users: %w", err)
		}
	}

	// Get users
	query := `
		SELECT id, email, password_hash, first_name, last_name,
			   status, email_verified, mfa_enabled, mfa_secret,
			   failed_logins, locked_until,
			   email_verification_token, email_verification_token_expires_at,
			   password_reset_token, password_reset_token_expires_at,
			   created_at, updated_at, last_login_at
		FROM users
		WHERE 1=1`

	if search != "" {
		query += ` AND (email ILIKE '%' || $1 || '%' OR first_name ILIKE '%' || $1 || '%' OR last_name ILIKE '%' || $1 || '%')`
		query += ` ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		err := r.db.SelectContext(ctx, &users, query, search, limit, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to list users: %w", err)
		}
	} else {
		query += ` ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		err := r.db.SelectContext(ctx, &users, query, limit, offset)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to list users: %w", err)
		}
	}

	return users, total, nil
}

// SuperAdminExists checks if any super admin user exists in the system
func (r *userRepository) SuperAdminExists(ctx context.Context) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM users WHERE is_super_admin = true)`

	var exists bool
	err := r.db.GetContext(ctx, &exists, query)
	if err != nil {
		return false, fmt.Errorf("failed to check super admin existence: %w", err)
	}

	return exists, nil
}

// AssignRole assigns a role to a user
func (r *userRepository) AssignRole(ctx context.Context, userID, roleID uuid.UUID) error {
	query := `
		INSERT INTO user_roles (user_id, role_id, assigned_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (user_id, role_id) DO NOTHING`

	_, err := r.db.ExecContext(ctx, query, userID, roleID)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}

	return nil
}
