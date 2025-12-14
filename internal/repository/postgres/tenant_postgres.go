package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
)

type tenantRepository struct {
	db *sqlx.DB
}

// NewTenantRepository creates a new PostgreSQL tenant repository
func NewTenantRepository(db *sqlx.DB) repository.TenantRepository {
	return &tenantRepository{db: db}
}

// GetByID retrieves a tenant by its ID
func (r *tenantRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	query := `
		SELECT id, app_id, name, slug, type, owner_id, max_users, current_users_count,
			   status, metadata, created_at, updated_at
		FROM tenants
		WHERE id = $1`

	var tenant domain.Tenant
	err := r.db.GetContext(ctx, &tenant, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("tenant not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get tenant by id: %w", err)
	}

	return &tenant, nil
}

// GetBySlug retrieves a tenant by its slug and app ID
func (r *tenantRepository) GetBySlug(ctx context.Context, appID uuid.UUID, slug string) (*domain.Tenant, error) {
	query := `
		SELECT id, app_id, name, slug, type, owner_id, max_users, current_users_count,
			   status, metadata, created_at, updated_at
		FROM tenants
		WHERE app_id = $1 AND slug = $2`

	var tenant domain.Tenant
	err := r.db.GetContext(ctx, &tenant, query, appID, slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("tenant not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	return &tenant, nil
}

// GetPublicTenant retrieves the "public" tenant for an app (or creates it if it doesn't exist)
func (r *tenantRepository) GetPublicTenant(ctx context.Context, appID uuid.UUID) (*domain.Tenant, error) {
	log.Printf("[TENANT_REPO] Getting public tenant for app: %s", appID)

	// Special case: base app has a fixed public tenant ID
	if appID == uuid.MustParse("7057e69d-818b-45db-b39b-9d1c84aca142") {
		return r.GetByID(ctx, domain.PublicTenantID)
	}

	// For other apps, try to find public tenant by slug
	tenant, err := r.GetBySlug(ctx, appID, "public")
	if err == nil {
		return tenant, nil
	}

	// If not found, the function get_public_tenant_id() in the database will create it
	// But we can also create it here in Go for consistency
	log.Printf("[TENANT_REPO] Public tenant not found for app %s, it should be created by DB function", appID)
	return nil, fmt.Errorf("public tenant not found for app: %w", err)
}

// Create inserts a new tenant into the database
func (r *tenantRepository) Create(ctx context.Context, tenant *domain.Tenant) error {
	query := `
		INSERT INTO tenants (
			id, app_id, name, slug, type, owner_id, max_users, current_users_count,
			status, metadata, created_at, updated_at
		) VALUES (
			:id, :app_id, :name, :slug, :type, :owner_id, :max_users, :current_users_count,
			:status, :metadata, :created_at, :updated_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, tenant)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// Update updates an existing tenant in the database
func (r *tenantRepository) Update(ctx context.Context, tenant *domain.Tenant) error {
	query := `
		UPDATE tenants
		SET name = :name,
			slug = :slug,
			type = :type,
			owner_id = :owner_id,
			max_users = :max_users,
			current_users_count = :current_users_count,
			status = :status,
			metadata = :metadata,
			updated_at = :updated_at
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, tenant)
	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("tenant not found")
	}

	return nil
}

// List retrieves tenants with pagination for a specific app
func (r *tenantRepository) List(ctx context.Context, appID uuid.UUID, limit, offset int) ([]*domain.Tenant, int, error) {
	var tenants []*domain.Tenant
	var total int

	// Count total
	countQuery := `SELECT COUNT(*) FROM tenants WHERE app_id = $1`
	err := r.db.GetContext(ctx, &total, countQuery, appID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count tenants: %w", err)
	}

	// Get paginated results
	query := `
		SELECT id, app_id, name, slug, type, owner_id, max_users, current_users_count,
			   status, metadata, created_at, updated_at
		FROM tenants
		WHERE app_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	err = r.db.SelectContext(ctx, &tenants, query, appID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list tenants: %w", err)
	}

	return tenants, total, nil
}
