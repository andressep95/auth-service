package service

import (
	"context"
	"errors"
	"fmt"
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
func (s *AppService) CreateApp(ctx context.Context, name, description string, redirectURIs, webOrigins []string, logoURL *string, primaryColor string) (*domain.App, error) {
	// Generate client_id from name (lowercase, replace spaces with hyphens)
	clientID := strings.ToLower(strings.ReplaceAll(name, " ", "-"))

	// Check if client_id already exists
	existing, _ := s.appRepo.GetByClientID(ctx, clientID)
	if existing != nil {
		return nil, errors.New("app with this name already exists")
	}

	// Set default values if not provided
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	if webOrigins == nil {
		webOrigins = []string{}
	}
	if primaryColor == "" {
		primaryColor = "#05C383" // Default green color
	}

	app := &domain.App{
		ID:               uuid.New(),
		Name:             name,
		ClientID:         clientID,
		ClientSecretHash: "placeholder", // To be implemented with OAuth2
		Description:      &description,
		RedirectURIs:     redirectURIs,
		WebOrigins:       webOrigins,
		LogoURL:          logoURL,
		PrimaryColor:     primaryColor,
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

	app, err := s.appRepo.GetByID(ctx, appID)
	if err != nil {
		fmt.Println("SERVICE: error", err)
		return nil, err
	}
	return app, nil
}
