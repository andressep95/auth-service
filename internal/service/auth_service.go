package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/andressep95/auth-service/internal/config"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/andressep95/auth-service/pkg/blacklist"
	"github.com/andressep95/auth-service/pkg/hash"
	"github.com/andressep95/auth-service/pkg/jwt"
	"github.com/google/uuid"
)

// Custom errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account is locked")
	ErrUserNotFound       = errors.New("user not found")
)

type AuthService struct {
	userRepo       repository.UserRepository
	tenantRepo     repository.TenantRepository
	sessionRepo    repository.SessionRepository
	roleRepo       repository.RoleRepository
	tokenService   *jwt.TokenService
	tokenBlacklist *blacklist.TokenBlacklist
	cfg            *config.Config
}

type LoginRequest struct {
	Email    string `json:"email" form:"email" validate:"required,email"`
	Password string `json:"password" form:"password" validate:"required,min=8"`
	AppID    string `json:"app_id" form:"app_id" validate:"omitempty,uuid"`       // Optional, defaults to base app
	TenantID string `json:"tenant_id" form:"tenant_id" validate:"omitempty,uuid"` // Optional, defaults to public tenant
}

type LoginResponse struct {
	Tokens *domain.TokenPair `json:"tokens"`
	User   *UserDTO          `json:"user"`
}

type UserDTO struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	TenantID  uuid.UUID `json:"tenant_id"`
}

func NewAuthService(
	userRepo repository.UserRepository,
	tenantRepo repository.TenantRepository,
	sessionRepo repository.SessionRepository,
	roleRepo repository.RoleRepository,
	tokenService *jwt.TokenService,
	tokenBlacklist *blacklist.TokenBlacklist,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:       userRepo,
		tenantRepo:     tenantRepo,
		sessionRepo:    sessionRepo,
		roleRepo:       roleRepo,
		tokenService:   tokenService,
		tokenBlacklist: tokenBlacklist,
		cfg:            cfg,
	}
}

func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*LoginResponse, error) {
	// Parse app ID (use base app if not provided)
	var appID uuid.UUID
	var err error

	if req.AppID == "" {
		// Use base app (7057e69d-818b-45db-b39b-9d1c84aca142)
		appID = uuid.MustParse("7057e69d-818b-45db-b39b-9d1c84aca142")
		log.Printf("[AUTH_SERVICE] No app_id provided, using base app: %s", appID)
	} else {
		appID, err = uuid.Parse(req.AppID)
		if err != nil {
			return nil, errors.New("invalid app_id format")
		}
	}

	// Parse and validate tenant_id (use public tenant if not provided)
	var tenantID uuid.UUID
	if req.TenantID == "" {
		// Get public tenant for this app
		publicTenant, err := s.tenantRepo.GetPublicTenant(ctx, appID)
		if err != nil || publicTenant == nil {
			return nil, errors.New("public tenant not found for this application")
		}
		tenantID = publicTenant.ID
		log.Printf("[AUTH_SERVICE] No tenant_id provided, using public tenant: %s", tenantID)
	} else {
		tenantID, err = uuid.Parse(req.TenantID)
		if err != nil {
			return nil, errors.New("invalid tenant_id format")
		}

		// Verify that the tenant exists and belongs to the app
		tenant, err := s.tenantRepo.GetByID(ctx, tenantID)
		if err != nil || tenant == nil {
			return nil, errors.New("tenant not found")
		}
		if tenant.AppID != appID {
			return nil, errors.New("tenant does not belong to this application")
		}
		log.Printf("[AUTH_SERVICE] Using tenant: %s (%s)", tenant.ID, tenant.Name)
	}

	// Get user by email, app, and tenant (multi-tenant)
	user, err := s.userRepo.GetByEmailAppAndTenant(ctx, req.Email, appID, tenantID)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	// Check if account is locked
	if user.Status == domain.UserStatusLocked {
		if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
			return nil, ErrAccountLocked
		}
		// Unlock account if lock period has expired
		if user.LockedUntil != nil && time.Now().After(*user.LockedUntil) {
			user.Status = domain.UserStatusActive
			user.FailedLogins = 0
			user.LockedUntil = nil
			if err := s.userRepo.Update(ctx, user); err != nil {
				return nil, err
			}
		}
	}

	// Verify password
	valid, err := hash.VerifyPassword(req.Password, user.PasswordHash)
	if err != nil {
		return nil, err
	}

	if !valid {
		// Handle failed login
		if err := s.handleFailedLogin(ctx, user); err != nil {
			return nil, err
		}
		return nil, ErrInvalidCredentials
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		return nil, errors.New("user account is not active")
	}

	// Reset failed login attempts on successful login
	if user.FailedLogins > 0 {
		if err := s.userRepo.ResetFailedLogins(ctx, user.ID); err != nil {
			return nil, err
		}
	}

	// Get user roles for the specific app
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID, appID)
	if err != nil {
		return nil, err
	}

	// Generate session ID first
	sessionID := uuid.New()

	// Generate token pair with session ID
	tokenPair, err := s.tokenService.GenerateTokenPair(user, roles, appID, &sessionID)
	if err != nil {
		return nil, err
	}

	// Hash the refresh token before storing
	hashedRefreshToken := hashToken(tokenPair.RefreshToken)

	// Create session with the pre-generated ID
	session := &domain.Session{
		ID:               sessionID,
		UserID:           user.ID,
		AppID:            appID,
		TenantID:         tenantID,
		RefreshTokenHash: hashedRefreshToken,
		ExpiresAt:        time.Now().Add(s.cfg.JWT.RefreshTokenExpiry),
		CreatedAt:        time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}

	// Update last login time
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		// Log error but don't fail the login
		// In production, use proper logging here
	}

	// Prepare response
	userDTO := &UserDTO{
		ID:        user.ID,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		TenantID:  tenantID,
	}

	return &LoginResponse{
		Tokens: tokenPair,
		User:   userDTO,
	}, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*domain.TokenPair, error) {
	// Validate the refresh token
	claims, err := s.tokenService.ValidateToken(refreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Verify it's a refresh token
	if claims.TokenType != "refresh" {
		return nil, errors.New("token is not a refresh token")
	}

	// Hash the refresh token to look it up in the database
	hashedRefreshToken := hashToken(refreshToken)

	// Get session by token hash
	session, err := s.sessionRepo.GetByToken(ctx, hashedRefreshToken)
	if err != nil {
		return nil, errors.New("session not found")
	}

	// Check if session is expired
	if time.Now().After(session.ExpiresAt) {
		// Delete expired session
		_ = s.sessionRepo.Delete(ctx, session.ID)
		return nil, errors.New("session expired")
	}

	// Get user
	user, err := s.userRepo.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Check if user is active
	if user.Status != domain.UserStatusActive {
		return nil, errors.New("user account is not active")
	}

	// Get user roles for the app
	roles, err := s.userRepo.GetUserRoles(ctx, user.ID, claims.AppID)
	if err != nil {
		return nil, err
	}

	// Generate new token pair with existing session ID
	sessionID := session.ID
	newTokenPair, err := s.tokenService.GenerateTokenPair(user, roles, claims.AppID, &sessionID)
	if err != nil {
		return nil, err
	}

	// Hash the new refresh token
	newHashedRefreshToken := hashToken(newTokenPair.RefreshToken)

	// Update session with new refresh token
	session.RefreshTokenHash = newHashedRefreshToken
	session.ExpiresAt = time.Now().Add(s.cfg.JWT.RefreshTokenExpiry)
	if err := s.sessionRepo.Update(ctx, session); err != nil {
		return nil, err
	}

	return newTokenPair, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string, accessToken string) error {
	// 1. Blacklist the access token immediately
	if accessToken != "" {
		// Validate and extract claims to get expiration
		claims, err := s.tokenService.ValidateToken(accessToken)
		if err == nil && claims.ExpiresAt != nil {
			// Calculate TTL until token expires
			expiresAt := claims.ExpiresAt.Time
			if err := s.tokenBlacklist.AddAccessToken(ctx, accessToken, expiresAt); err != nil {
				// Log error but don't fail logout
				// The session will still be deleted
			}
		}
	}

	// 2. Hash the refresh token
	hashedRefreshToken := hashToken(refreshToken)

	// 3. Delete session by token
	if err := s.sessionRepo.DeleteByToken(ctx, hashedRefreshToken); err != nil {
		return errors.New("failed to logout")
	}

	return nil
}

// handleFailedLogin increments failed login count and locks account if threshold is reached
func (s *AuthService) handleFailedLogin(ctx context.Context, user *domain.User) error {
	// Increment failed login count
	if err := s.userRepo.IncrementFailedLogins(ctx, user.ID); err != nil {
		return err
	}

	// Reload user to get updated failed login count
	updatedUser, err := s.userRepo.GetByID(ctx, user.ID)
	if err != nil {
		return err
	}

	// Check if we should lock the account
	if updatedUser.FailedLogins >= s.cfg.Auth.MaxFailedLogins {
		lockUntil := time.Now().Add(s.cfg.Auth.LockDuration)
		updatedUser.Status = domain.UserStatusLocked
		updatedUser.LockedUntil = &lockUntil

		if err := s.userRepo.Update(ctx, updatedUser); err != nil {
			return err
		}
	}

	return nil
}

// ChangePassword changes user password and invalidates all sessions
func (s *AuthService) ChangePassword(ctx context.Context, userID uuid.UUID, oldPassword, newPassword string) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return ErrUserNotFound
	}

	valid, err := hash.VerifyPassword(oldPassword, user.PasswordHash)
	if err != nil || !valid {
		return ErrInvalidCredentials
	}

	newHash, err := hash.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = newHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	// Invalidate all sessions and blacklist tokens
	return s.InvalidateAllUserSessions(ctx, userID)
}

// InvalidateAllUserSessions closes all sessions and blacklists tokens
func (s *AuthService) InvalidateAllUserSessions(ctx context.Context, userID uuid.UUID) error {
	sessions, err := s.sessionRepo.GetByUserID(ctx, userID)
	if err != nil {
		return err
	}

	for _, session := range sessions {
		_ = s.sessionRepo.Delete(ctx, session.ID)
	}

	// Blacklist all tokens issued before NOW for 24h (longer than max token lifetime)
	return s.tokenBlacklist.BlacklistUser(ctx, userID.String(), 24*time.Hour)
}

// hashToken creates a SHA-256 hash of the token
func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// RegisterWithInvitationRequest represents the registration with invitation request
type RegisterWithInvitationRequest struct {
	Token       string `json:"token" validate:"required"`
	Email       string `json:"email" validate:"required,email"`
	Password    string `json:"password" validate:"required,min=8"`
	FirstName   string `json:"first_name" validate:"required"`
	LastName    string `json:"last_name" validate:"required"`
	PhoneNumber string `json:"phone_number,omitempty"`
}

// RegisterWithInvitation registers a new user using an invitation token
func (s *AuthService) RegisterWithInvitation(ctx context.Context, req RegisterWithInvitationRequest, tenantService *TenantService, appService *AppService) (*LoginResponse, string, error) {
	// 1. Validate invitation token
	invitation, tenant, err := tenantService.ValidateInvitationToken(ctx, req.Token)
	if err != nil {
		return nil, "", errors.New("invalid or expired invitation token")
	}

	// 2. Check if email already exists in this tenant
	existingUser, _ := s.userRepo.GetByEmailAppAndTenant(ctx, req.Email, tenant.AppID, tenant.ID)
	if existingUser != nil {
		return nil, "", errors.New("email already registered in this workspace")
	}

	// 3. Check tenant quota
	if tenant.MaxUsers != nil && tenant.CurrentUsersCount >= *tenant.MaxUsers {
		return nil, "", errors.New("workspace has reached maximum user limit")
	}

	// 4. Hash password
	passwordHash, err := hash.HashPassword(req.Password)
	if err != nil {
		return nil, "", err
	}

	// 5. Create user
	user := &domain.User{
		ID:            uuid.New(),
		AppID:         tenant.AppID,
		TenantID:      tenant.ID,
		Email:         req.Email,
		PasswordHash:  passwordHash,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Status:        domain.UserStatusActive,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, "", err
	}

	// 6. Assign role (from invitation or default "user" role)
	var roleID uuid.UUID
	if invitation.RoleID != nil {
		roleID = *invitation.RoleID
	} else {
		// Get default "user" role for this app
		role, err := s.roleRepo.GetByName(ctx, tenant.AppID, "user")
		if err != nil || role == nil {
			return nil, "", errors.New("default user role not found")
		}
		roleID = role.ID
	}

	if err := s.roleRepo.AssignRoleToUser(ctx, user.ID, roleID); err != nil {
		// Rollback user creation if role assignment fails
		_ = s.userRepo.Delete(ctx, user.ID)
		return nil, "", errors.New("failed to assign role to user")
	}

	// 7. Increment invitation usage counter
	if err := tenantService.UseInvitation(ctx, invitation.ID); err != nil {
		log.Printf("Warning: Failed to increment invitation usage: %v", err)
	}

	// 8. Get user roles for token
	roles, err := s.roleRepo.GetUserRolesByApp(ctx, user.ID, user.AppID)
	if err != nil {
		roles = []*domain.Role{} // Empty roles if fetch fails
	}

	roleNames := make([]string, len(roles))
	for i, role := range roles {
		roleNames[i] = role.Name
	}

	// 9. Generate tokens
	tokenPair, err := s.tokenService.GenerateTokenPair(user, roleNames, user.AppID, nil)
	if err != nil {
		return nil, "", err
	}

	// 10. Create session
	refreshTokenHash := hashToken(tokenPair.RefreshToken)
	session := &domain.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		AppID:            user.AppID,
		TenantID:         user.TenantID,
		RefreshTokenHash: refreshTokenHash,
		ExpiresAt:        tokenPair.ExpiresAt.Add(7 * 24 * time.Hour), // 7 days
		CreatedAt:        time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		log.Printf("Warning: Failed to create session: %v", err)
	}

	// 11. Get app redirect URL
	app, err := appService.GetAppByID(ctx, tenant.AppID.String())
	if err != nil {
		return nil, "", errors.New("app not found")
	}

	// 12. Build redirect URL with tokens
	redirectURL := fmt.Sprintf("%s?access_token=%s&refresh_token=%s&tenant_id=%s",
		app.RedirectURIs[0],
		tokenPair.AccessToken,
		tokenPair.RefreshToken,
		tenant.ID.String(),
	)

	response := &LoginResponse{
		Tokens: tokenPair,
		User: &UserDTO{
			ID:        user.ID,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			TenantID:  user.TenantID,
		},
	}

	return response, redirectURL, nil
}
