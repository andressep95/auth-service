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
	"github.com/lib/pq"
)

type appRepository struct {
	db *sqlx.DB
}

func NewAppRepository(db *sqlx.DB) repository.AppRepository {
	return &appRepository{db: db}
}

func (r *appRepository) Create(ctx context.Context, app *domain.App) error {
	app.CreatedAt = time.Now()
	app.UpdatedAt = time.Now()

	query := `
		INSERT INTO apps (id, name, client_id, client_secret_hash, description, redirect_uris, web_origins, logo_url, primary_color, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.ExecContext(ctx, query,
		app.ID, app.Name, app.ClientID, app.ClientSecretHash, app.Description,
		pq.Array(app.RedirectURIs), pq.Array(app.WebOrigins), app.LogoURL, app.PrimaryColor,
		app.CreatedAt, app.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create app: %w", err)
	}

	return nil
}

func (r *appRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.App, error) {
	query := `
		SELECT id, name, client_id, client_secret_hash, description, redirect_uris, web_origins, logo_url, primary_color, created_at, updated_at
		FROM apps
		WHERE id = $1`

	var app domain.App
	err := r.db.GetContext(ctx, &app, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("app not found")
		}
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	return &app, nil
}

func (r *appRepository) GetByClientID(ctx context.Context, clientID string) (*domain.App, error) {
	query := `
		SELECT id, name, client_id, client_secret_hash, description, redirect_uris, web_origins, logo_url, primary_color, created_at, updated_at
		FROM apps
		WHERE client_id = $1`

	var app domain.App
	err := r.db.GetContext(ctx, &app, query, clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get app: %w", err)
	}

	return &app, nil
}

func (r *appRepository) List(ctx context.Context) ([]*domain.App, error) {
	query := `
		SELECT id, name, client_id, client_secret_hash, description, redirect_uris, web_origins, logo_url, primary_color, created_at, updated_at
		FROM apps
		ORDER BY created_at DESC`

	var apps []*domain.App
	err := r.db.SelectContext(ctx, &apps, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list apps: %w", err)
	}

	return apps, nil
}

func (r *appRepository) Update(ctx context.Context, app *domain.App) error {
	app.UpdatedAt = time.Now()

	query := `
		UPDATE apps
		SET name = $1, description = $2, redirect_uris = $3, web_origins = $4, logo_url = $5, primary_color = $6, updated_at = $7
		WHERE id = $8`

	result, err := r.db.ExecContext(ctx, query,
		app.Name, app.Description, pq.Array(app.RedirectURIs), pq.Array(app.WebOrigins),
		app.LogoURL, app.PrimaryColor, app.UpdatedAt, app.ID)
	if err != nil {
		return fmt.Errorf("failed to update app: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("app not found")
	}

	return nil
}

func (r *appRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM apps WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete app: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("app not found")
	}

	return nil
}
