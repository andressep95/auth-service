package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
)

type invitationRepository struct {
	db *sqlx.DB
}

// NewInvitationRepository creates a new PostgreSQL invitation repository
func NewInvitationRepository(db *sqlx.DB) repository.InvitationRepository {
	return &invitationRepository{db: db}
}

// Create inserts a new invitation into the database
func (r *invitationRepository) Create(ctx context.Context, invitation *domain.TenantInvitation) error {
	query := `
		INSERT INTO tenant_invitations (
			id, tenant_id, token_hash, created_by, role_id, max_uses,
			current_uses, expires_at, status, created_at, updated_at
		) VALUES (
			:id, :tenant_id, :token_hash, :created_by, :role_id, :max_uses,
			:current_uses, :expires_at, :status, :created_at, :updated_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, invitation)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	return nil
}

// GetByID retrieves an invitation by its ID
func (r *invitationRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.TenantInvitation, error) {
	query := `
		SELECT id, tenant_id, token_hash, created_by, role_id, max_uses,
			   current_uses, expires_at, status, created_at, updated_at
		FROM tenant_invitations
		WHERE id = $1`

	var invitation domain.TenantInvitation
	err := r.db.GetContext(ctx, &invitation, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invitation not found")
		}
		return nil, fmt.Errorf("failed to get invitation: %w", err)
	}

	return &invitation, nil
}

// GetByTokenHash retrieves an invitation by its token hash
func (r *invitationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.TenantInvitation, error) {
	query := `
		SELECT id, tenant_id, token_hash, created_by, role_id, max_uses,
			   current_uses, expires_at, status, created_at, updated_at
		FROM tenant_invitations
		WHERE token_hash = $1`

	var invitation domain.TenantInvitation
	err := r.db.GetContext(ctx, &invitation, query, tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("invitation not found")
		}
		return nil, fmt.Errorf("failed to get invitation by token: %w", err)
	}

	return &invitation, nil
}

// Update updates an existing invitation
func (r *invitationRepository) Update(ctx context.Context, invitation *domain.TenantInvitation) error {
	query := `
		UPDATE tenant_invitations
		SET tenant_id = :tenant_id,
			token_hash = :token_hash,
			created_by = :created_by,
			role_id = :role_id,
			max_uses = :max_uses,
			current_uses = :current_uses,
			expires_at = :expires_at,
			status = :status,
			updated_at = :updated_at
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, invitation)
	if err != nil {
		return fmt.Errorf("failed to update invitation: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("invitation not found")
	}

	return nil
}

// IncrementUses increments the current_uses counter
func (r *invitationRepository) IncrementUses(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE tenant_invitations
		SET current_uses = current_uses + 1,
			updated_at = NOW()
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to increment invitation uses: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("invitation not found")
	}

	return nil
}

// ListByTenantID retrieves invitations for a specific tenant with pagination
func (r *invitationRepository) ListByTenantID(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*domain.TenantInvitation, int, error) {
	var invitations []*domain.TenantInvitation
	var total int

	// Count total
	countQuery := `SELECT COUNT(*) FROM tenant_invitations WHERE tenant_id = $1`
	err := r.db.GetContext(ctx, &total, countQuery, tenantID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count invitations: %w", err)
	}

	// Get paginated results
	query := `
		SELECT id, tenant_id, token_hash, created_by, role_id, max_uses,
			   current_uses, expires_at, status, created_at, updated_at
		FROM tenant_invitations
		WHERE tenant_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	err = r.db.SelectContext(ctx, &invitations, query, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list invitations: %w", err)
	}

	return invitations, total, nil
}

// Delete removes an invitation from the database
func (r *invitationRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM tenant_invitations WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete invitation: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("invitation not found")
	}

	return nil
}
