package service

import (
	"context"
	"errors"
	"strings"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/google/uuid"
)

type AppService struct {
	appRepo repository.AppRepository
}

func NewAppService(appRepo repository.AppRepository) *AppService {
	return &AppService{
		appRepo: appRepo,
	}
}

// CreateApp creates a new application
func (s *AppService) CreateApp(ctx context.Context, name, description string) (*domain.App, error) {
	// Generate client_id from name (lowercase, replace spaces with hyphens)
	clientID := strings.ToLower(strings.ReplaceAll(name, " ", "-"))

	// Check if client_id already exists
	existing, _ := s.appRepo.GetByClientID(ctx, clientID)
	if existing != nil {
		return nil, errors.New("app with this name already exists")
	}

	app := &domain.App{
		ID:               uuid.New(), // UUID aleatorio
		Name:             name,
		ClientID:         clientID,
		ClientSecretHash: "placeholder", // No usado por ahora
		Description:      description,
	}

	if err := s.appRepo.Create(ctx, app); err != nil {
		return nil, err
	}

	return app, nil
}

// ListApps returns all applications
func (s *AppService) ListApps(ctx context.Context) ([]*domain.App, error) {
	return s.appRepo.List(ctx)
}

// GetAppByID returns an app by ID
func (s *AppService) GetAppByID(ctx context.Context, id string) (*domain.App, error) {
	appID, err := uuid.Parse(id)
	if err != nil {
		return nil, errors.New("invalid app ID")
	}

	return s.appRepo.GetByID(ctx, appID)
}
