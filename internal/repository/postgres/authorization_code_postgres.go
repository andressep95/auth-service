package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

type authorizationCodeRepository struct {
	db *sqlx.DB
}

func NewAuthorizationCodeRepository(db *sqlx.DB) repository.AuthorizationCodeRepository {
	return &authorizationCodeRepository{db: db}
}

func (r *authorizationCodeRepository) Create(ctx context.Context, code *domain.AuthorizationCode) error {
	code.CreatedAt = time.Now()

	query := `
		INSERT INTO authorization_codes (
			id, code_hash, app_id, user_id, redirect_uri, scope, state,
			code_challenge, code_challenge_method, used, expires_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := r.db.ExecContext(ctx, query,
		code.ID, code.CodeHash, code.AppID, code.UserID, code.RedirectURI,
		code.Scope, code.State, code.CodeChallenge, code.CodeChallengeMethod,
		code.Used, code.ExpiresAt, code.CreatedAt)

	if err != nil {
		return fmt.Errorf("failed to create authorization code: %w", err)
	}

	return nil
}

func (r *authorizationCodeRepository) GetByCodeHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	query := `
		SELECT id, code_hash, app_id, user_id, redirect_uri, scope, state,
		       code_challenge, code_challenge_method, used, expires_at, created_at
		FROM authorization_codes
		WHERE code_hash = $1`

	var code domain.AuthorizationCode
	err := r.db.GetContext(ctx, &code, query, codeHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("authorization code not found")
		}
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}

	return &code, nil
}

func (r *authorizationCodeRepository) MarkAsUsed(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE authorization_codes
		SET used = TRUE
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to mark authorization code as used: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("authorization code not found")
	}

	return nil
}

func (r *authorizationCodeRepository) DeleteExpired(ctx context.Context) error {
	query := `
		DELETE FROM authorization_codes
		WHERE expires_at < NOW()`

	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired authorization codes: %w", err)
	}

	return nil
}

func (r *authorizationCodeRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	query := `
		DELETE FROM authorization_codes
		WHERE user_id = $1`

	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete authorization codes by user ID: %w", err)
	}

	return nil
}
