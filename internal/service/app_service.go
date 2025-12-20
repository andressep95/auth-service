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

// AppResolution holds the result of resolving an app from origin
type AppResolution struct {
	App                *domain.App
	SuggestedRedirectURI string
}

// ResolveAppFromOrigin automatically detects app and redirect_uri from Origin header
// This simplifies frontend integration - they only need to point to auth service
func (s *AppService) ResolveAppFromOrigin(ctx context.Context, origin string) (*AppResolution, error) {
	if origin == "" {
		return nil, errors.New("origin is required")
	}

	// Find app by web origin
	app, err := s.appRepo.GetByWebOrigin(ctx, origin)
	if err != nil {
		return nil, fmt.Errorf("failed to find app: %w", err)
	}

	if app == nil {
		return nil, fmt.Errorf("no app registered for origin: %s", origin)
	}

	// Suggest redirect_uri: Find first redirect_uri that matches the origin
	suggestedRedirectURI := ""
	for _, redirectURI := range app.RedirectURIs {
		// Check if redirect_uri starts with the origin
		if strings.HasPrefix(redirectURI, origin) {
			suggestedRedirectURI = redirectURI
			break
		}
	}

	// If no exact match, use first redirect_uri (if exists)
	if suggestedRedirectURI == "" && len(app.RedirectURIs) > 0 {
		suggestedRedirectURI = app.RedirectURIs[0]
	}

	return &AppResolution{
		App:                app,
		SuggestedRedirectURI: suggestedRedirectURI,
	}, nil
}
