package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/google/uuid"
)

type TenantService struct {
	tenantRepo     repository.TenantRepository
	invitationRepo repository.InvitationRepository
	userRepo       repository.UserRepository
}

func NewTenantService(
	tenantRepo repository.TenantRepository,
	invitationRepo repository.InvitationRepository,
	userRepo repository.UserRepository,
) *TenantService {
	return &TenantService{
		tenantRepo:     tenantRepo,
		invitationRepo: invitationRepo,
		userRepo:       userRepo,
	}
}

// CreateTenant creates a new tenant within an app
func (s *TenantService) CreateTenant(ctx context.Context, appID uuid.UUID, name, slug string, tenantType domain.TenantType, ownerID *uuid.UUID, maxUsers *int) (*domain.Tenant, error) {
	// Validate slug format (lowercase, alphanumeric + hyphens, 3-100 chars)
	if slug == "" {
		slug = generateSlugFromName(name)
	}

	if !isValidSlug(slug) {
		return nil, errors.New("invalid slug format: must be lowercase alphanumeric with hyphens, 3-100 characters")
	}

	// Check if slug already exists for this app
	existing, _ := s.tenantRepo.GetBySlug(ctx, appID, slug)
	if existing != nil {
		return nil, fmt.Errorf("tenant with slug '%s' already exists in this app", slug)
	}

	// Validate tenant type
	if tenantType != domain.TenantTypePublic && tenantType != domain.TenantTypeWorkspace && tenantType != domain.TenantTypeEnterprise {
		tenantType = domain.TenantTypeWorkspace // Default
	}

	tenant := &domain.Tenant{
		ID:                uuid.New(),
		AppID:             appID,
		Name:              name,
		Slug:              slug,
		Type:              tenantType,
		OwnerID:           ownerID,
		MaxUsers:          maxUsers,
		CurrentUsersCount: 0,
		Status:            domain.TenantStatusActive,
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	if err := s.tenantRepo.Create(ctx, tenant); err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	return tenant, nil
}

// GetTenantByID retrieves a tenant by ID
func (s *TenantService) GetTenantByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	return s.tenantRepo.GetByID(ctx, id)
}

// GetTenantBySlug retrieves a tenant by slug and app ID
func (s *TenantService) GetTenantBySlug(ctx context.Context, appID uuid.UUID, slug string) (*domain.Tenant, error) {
	return s.tenantRepo.GetBySlug(ctx, appID, slug)
}

// UpdateTenant updates tenant information
func (s *TenantService) UpdateTenant(ctx context.Context, id uuid.UUID, name, slug *string, maxUsers *int, status *domain.TenantStatus) (*domain.Tenant, error) {
	tenant, err := s.tenantRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update fields if provided
	if name != nil && *name != "" {
		tenant.Name = *name
	}

	if slug != nil && *slug != "" {
		if !isValidSlug(*slug) {
			return nil, errors.New("invalid slug format")
		}
		// Check if new slug conflicts with another tenant
		if *slug != tenant.Slug {
			existing, _ := s.tenantRepo.GetBySlug(ctx, tenant.AppID, *slug)
			if existing != nil && existing.ID != id {
				return nil, fmt.Errorf("slug '%s' already exists", *slug)
			}
			tenant.Slug = *slug
		}
	}

	if maxUsers != nil {
		tenant.MaxUsers = maxUsers
	}

	if status != nil {
		tenant.Status = *status
	}

	tenant.UpdatedAt = time.Now()

	if err := s.tenantRepo.Update(ctx, tenant); err != nil {
		return nil, fmt.Errorf("failed to update tenant: %w", err)
	}

	return tenant, nil
}

// ListTenants retrieves tenants for an app with pagination
func (s *TenantService) ListTenants(ctx context.Context, appID uuid.UUID, limit, offset int) ([]*domain.Tenant, int, error) {
	return s.tenantRepo.List(ctx, appID, limit, offset)
}

// CreateInvitation creates a new invitation token for a tenant
func (s *TenantService) CreateInvitation(ctx context.Context, tenantID, createdBy uuid.UUID, roleID *uuid.UUID, maxUses *int, expiresInHours int) (*domain.TenantInvitation, string, error) {
	// Validate tenant exists
	tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
	if err != nil {
		return nil, "", fmt.Errorf("tenant not found: %w", err)
	}

	if tenant.Status != domain.TenantStatusActive {
		return nil, "", errors.New("cannot create invitation for inactive tenant")
	}

	// Generate random token (32 bytes = 256 bits)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate token: %w", err)
	}

	// Encode token as base64 for URL-safe transmission
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash token with SHA-256 for storage
	hash := sha256.Sum256([]byte(token))
	tokenHash := fmt.Sprintf("%x", hash[:])

	// Calculate expiration
	expiresAt := time.Now().Add(time.Duration(expiresInHours) * time.Hour)

	invitation := &domain.TenantInvitation{
		ID:          uuid.New(),
		TenantID:    tenantID,
		TokenHash:   tokenHash,
		CreatedBy:   createdBy,
		RoleID:      roleID,
		MaxUses:     maxUses,
		CurrentUses: 0,
		ExpiresAt:   expiresAt,
		Status:      domain.InvitationStatusActive,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := s.invitationRepo.Create(ctx, invitation); err != nil {
		return nil, "", fmt.Errorf("failed to create invitation: %w", err)
	}

	// Return both the invitation and the plain token (only time it's exposed)
	return invitation, token, nil
}

// ValidateInvitationToken validates an invitation token
func (s *TenantService) ValidateInvitationToken(ctx context.Context, token string) (*domain.TenantInvitation, *domain.Tenant, error) {
	// Hash the provided token
	hash := sha256.Sum256([]byte(token))
	tokenHash := fmt.Sprintf("%x", hash[:])

	// Find invitation by hash
	invitation, err := s.invitationRepo.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, errors.New("invalid invitation token")
	}

	// Check if invitation is valid
	if !invitation.IsValid() {
		// Update status if expired
		if time.Now().After(invitation.ExpiresAt) && invitation.Status == domain.InvitationStatusActive {
			invitation.Status = domain.InvitationStatusExpired
			invitation.UpdatedAt = time.Now()
			_ = s.invitationRepo.Update(ctx, invitation)
		}
		return nil, nil, errors.New("invitation is no longer valid")
	}

	// Get tenant information
	tenant, err := s.tenantRepo.GetByID(ctx, invitation.TenantID)
	if err != nil {
		return nil, nil, errors.New("tenant not found")
	}

	if tenant.Status != domain.TenantStatusActive {
		return nil, nil, errors.New("tenant is not active")
	}

	return invitation, tenant, nil
}

// UseInvitation increments the use counter of an invitation
func (s *TenantService) UseInvitation(ctx context.Context, invitationID uuid.UUID) error {
	return s.invitationRepo.IncrementUses(ctx, invitationID)
}

// RevokeInvitation revokes an active invitation
func (s *TenantService) RevokeInvitation(ctx context.Context, invitationID uuid.UUID) error {
	invitation, err := s.invitationRepo.GetByID(ctx, invitationID)
	if err != nil {
		return err
	}

	invitation.Status = domain.InvitationStatusRevoked
	invitation.UpdatedAt = time.Now()

	return s.invitationRepo.Update(ctx, invitation)
}

// ListInvitations lists invitations for a tenant
func (s *TenantService) ListInvitations(ctx context.Context, tenantID uuid.UUID, limit, offset int) ([]*domain.TenantInvitation, int, error) {
	return s.invitationRepo.ListByTenantID(ctx, tenantID, limit, offset)
}

// Helper functions

// generateSlugFromName creates a URL-friendly slug from a name
func generateSlugFromName(name string) string {
	slug := strings.ToLower(name)
	// Replace spaces and special characters with hyphens
	slug = regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(slug, "-")
	// Remove leading/trailing hyphens
	slug = strings.Trim(slug, "-")
	// Limit to 100 characters
	if len(slug) > 100 {
		slug = slug[:100]
	}
	return slug
}

// isValidSlug checks if a slug meets the format requirements
func isValidSlug(slug string) bool {
	if len(slug) < 3 || len(slug) > 100 {
		return false
	}
	matched, _ := regexp.MatchString(`^[a-z0-9-]+$`, slug)
	return matched
}
