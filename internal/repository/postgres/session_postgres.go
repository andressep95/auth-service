package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
)

type sessionRepository struct {
	db *sqlx.DB
}

// NewSessionRepository creates a new PostgreSQL session repository
func NewSessionRepository(db *sqlx.DB) repository.SessionRepository {
	return &sessionRepository{db: db}
}

// Create inserts a new session into the database
func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, refresh_token_hash, user_agent,
			ip_address, expires_at, created_at
		) VALUES (
			:id, :user_id, :refresh_token_hash, :user_agent,
			:ip_address, :expires_at, :created_at
		)`

	_, err := r.db.NamedExecContext(ctx, query, session)
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetByID retrieves a session by its ID
func (r *sessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent,
			   ip_address, expires_at, created_at
		FROM sessions
		WHERE id = $1`

	var session domain.Session
	err := r.db.GetContext(ctx, &session, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found: %w", err)
		}
		return nil, fmt.Errorf("failed to get session by id: %w", err)
	}

	return &session, nil
}

// GetByToken retrieves a session by its token hash
func (r *sessionRepository) GetByToken(ctx context.Context, tokenHash string) (*domain.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent,
			   ip_address, expires_at, created_at
		FROM sessions
		WHERE refresh_token_hash = $1 AND expires_at > $2`

	var session domain.Session
	err := r.db.GetContext(ctx, &session, query, tokenHash, time.Now())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session not found or expired: %w", err)
		}
		return nil, fmt.Errorf("failed to get session by token: %w", err)
	}

	return &session, nil
}

// GetByUserID retrieves all sessions for a specific user
func (r *sessionRepository) GetByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.Session, error) {
	query := `
		SELECT id, user_id, refresh_token_hash, user_agent,
			   ip_address, expires_at, created_at
		FROM sessions
		WHERE user_id = $1 AND expires_at > $2
		ORDER BY created_at DESC`

	var sessions []*domain.Session
	err := r.db.SelectContext(ctx, &sessions, query, userID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions by user id: %w", err)
	}

	return sessions, nil
}

// Update updates an existing session in the database
func (r *sessionRepository) Update(ctx context.Context, session *domain.Session) error {
	query := `
		UPDATE sessions
		SET user_id = :user_id,
			refresh_token_hash = :refresh_token_hash,
			user_agent = :user_agent,
			ip_address = :ip_address,
			expires_at = :expires_at
		WHERE id = :id`

	result, err := r.db.NamedExecContext(ctx, query, session)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// Delete removes a session from the database by ID
func (r *sessionRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM sessions WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// DeleteByToken removes a session from the database by token hash
func (r *sessionRepository) DeleteByToken(ctx context.Context, tokenHash string) error {
	query := `DELETE FROM sessions WHERE refresh_token_hash = $1`

	result, err := r.db.ExecContext(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("failed to delete session by token: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// DeleteExpired removes all expired sessions from the database
func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at <= $1`

	_, err := r.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	return nil
}
