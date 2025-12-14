package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/andressep95/auth-service/internal/config"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/andressep95/auth-service/pkg/email"
	"github.com/andressep95/auth-service/pkg/hash"
	"github.com/google/uuid"
)

type UserService struct {
	userRepo     repository.UserRepository
	tenantRepo   repository.TenantRepository
	appRepo      repository.AppRepository
	sessionRepo  repository.SessionRepository
	authService  *AuthService
	emailService email.EmailService
	cfg          *config.Config
}

type RegisterRequest struct {
	AppID     string `json:"app_id" form:"app_id" validate:"omitempty,uuid"`            // Optional, defaults to base app
	TenantID  string `json:"tenant_id" form:"tenant_id" validate:"omitempty,uuid"`      // Optional, defaults to public tenant
	Email     string `json:"email" form:"email" validate:"required,email"`
	Password  string `json:"password" form:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" form:"first_name" validate:"required"`
	LastName  string `json:"last_name" form:"last_name" validate:"required"`
	PhoneNumber string `json:"phone_number,omitempty" form:"phone_number"`
}

func NewUserService(userRepo repository.UserRepository, tenantRepo repository.TenantRepository, appRepo repository.AppRepository, sessionRepo repository.SessionRepository, emailService email.EmailService, cfg *config.Config) *UserService {
	return &UserService{
		userRepo:     userRepo,
		tenantRepo:   tenantRepo,
		appRepo:      appRepo,
		sessionRepo:  sessionRepo,
		emailService: emailService,
		cfg:          cfg,
	}
}

// SetAuthService sets the auth service (to avoid circular dependency)
func (s *UserService) SetAuthService(authService *AuthService) {
	s.authService = authService
}

func (s *UserService) Register(ctx context.Context, req RegisterRequest) (*domain.User, error) {
	// Parse and validate app_id (use base app if not provided)
	var appID uuid.UUID
	var err error

	if req.AppID == "" {
		// Use base app (7057e69d-818b-45db-b39b-9d1c84aca142)
		appID = uuid.MustParse("7057e69d-818b-45db-b39b-9d1c84aca142")
		log.Printf("[USER_SERVICE] No app_id provided, using base app: %s", appID)
	} else {
		appID, err = uuid.Parse(req.AppID)
		if err != nil {
			return nil, errors.New("invalid app_id format")
		}
	}

	// Verify that the app exists
	app, err := s.appRepo.GetByID(ctx, appID)
	if err != nil || app == nil {
		return nil, errors.New("application not found")
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
		log.Printf("[USER_SERVICE] No tenant_id provided, using public tenant: %s", tenantID)
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
		log.Printf("[USER_SERVICE] Using tenant: %s (%s)", tenant.ID, tenant.Name)
	}

	// Check if user already exists in this app + tenant
	existingUser, err := s.userRepo.GetByEmailAppAndTenant(ctx, req.Email, appID, tenantID)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists in this tenant")
	}

	// Hash password
	passwordHash, err := hash.HashPassword(req.Password)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	// Generate email verification token (32 bytes = 64 hex chars)
	token, err := generateSecureToken(32)
	if err != nil {
		return nil, errors.New("failed to generate verification token")
	}

	// Token expires in 24 hours
	tokenExpiry := time.Now().Add(24 * time.Hour)

	// Create user
	user := &domain.User{
		ID:                              uuid.New(),
		AppID:                           appID,
		TenantID:                        tenantID,
		Email:                           req.Email,
		PasswordHash:                    passwordHash,
		FirstName:                       req.FirstName,
		LastName:                        req.LastName,
		Status:                          domain.UserStatusActive,
		EmailVerified:                   false,
		MFAEnabled:                      false,
		FailedLogins:                    0,
		EmailVerificationToken:          &token,
		EmailVerificationTokenExpiresAt: &tokenExpiry,
		CreatedAt:                       time.Now(),
		UpdatedAt:                       time.Now(),
	}

	// Save user to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, errors.New("failed to create user")
	}

	// Send verification email (async - don't fail registration if email fails)
	if s.cfg.Email.Enabled && s.emailService != nil {
		go func() {
			emailCtx := context.Background()
			if err := s.emailService.SendVerificationEmail(emailCtx, user.Email, user.FirstName, token); err != nil {
				// Log error but don't fail the registration
				fmt.Printf("Failed to send verification email to %s: %v\n", user.Email, err)
			}
		}()
	}

	return user, nil
}

func (s *UserService) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user, err := s.userRepo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func (s *UserService) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	return user, nil
}

func (s *UserService) Update(ctx context.Context, user *domain.User) error {
	// Validate that user exists
	existingUser, err := s.userRepo.GetByID(ctx, user.ID)
	if err != nil {
		return err
	}

	if existingUser == nil {
		return ErrUserNotFound
	}

	// Update timestamp
	user.UpdatedAt = time.Now()

	// Update user
	if err := s.userRepo.Update(ctx, user); err != nil {
		return errors.New("failed to update user")
	}

	return nil
}

// VerifyEmail verifies a user's email with the provided token
func (s *UserService) VerifyEmail(ctx context.Context, token string) error {
	// Find user by verification token
	user, err := s.userRepo.GetByVerificationToken(ctx, token)
	if err != nil || user == nil {
		return errors.New("invalid or expired verification token")
	}

	// Check if token is expired
	if user.EmailVerificationTokenExpiresAt != nil && time.Now().After(*user.EmailVerificationTokenExpiresAt) {
		return errors.New("verification token has expired")
	}

	// Update user: mark as verified and clear token
	user.EmailVerified = true
	user.EmailVerificationToken = nil
	user.EmailVerificationTokenExpiresAt = nil
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return errors.New("failed to verify email")
	}

	// Send welcome email (async)
	if s.cfg.Email.Enabled && s.emailService != nil {
		go func() {
			emailCtx := context.Background()
			if err := s.emailService.SendWelcomeEmail(emailCtx, user.Email, user.FirstName); err != nil {
				fmt.Printf("Failed to send welcome email to %s: %v\n", user.Email, err)
			}
		}()
	}

	return nil
}

// ResendVerificationEmail generates a new verification token and sends it
func (s *UserService) ResendVerificationEmail(ctx context.Context, email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return errors.New("user not found")
	}

	// Check if already verified
	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Generate new token
	token, err := generateSecureToken(32)
	if err != nil {
		return errors.New("failed to generate verification token")
	}

	// Token expires in 24 hours
	tokenExpiry := time.Now().Add(24 * time.Hour)

	// Update user with new token
	user.EmailVerificationToken = &token
	user.EmailVerificationTokenExpiresAt = &tokenExpiry
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return errors.New("failed to update verification token")
	}

	// Send verification email
	if s.cfg.Email.Enabled && s.emailService != nil {
		if err := s.emailService.SendVerificationEmail(ctx, user.Email, user.FirstName, token); err != nil {
			return errors.New("failed to send verification email")
		}
	}

	return nil
}

// RequestPasswordReset generates a password reset token and sends it via email
func (s *UserService) RequestPasswordReset(ctx context.Context, email, appIDStr string) error {
	log.Printf("[USER_SERVICE] Password reset requested for email: %s, app_id: %s", email, appIDStr)

	// Parse app_id
	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		log.Printf("[USER_SERVICE] Invalid app_id format: %s", appIDStr)
		return nil // Don't reveal error for security
	}

	// Get user by email and app (multi-tenant)
	user, err := s.userRepo.GetByEmailAndApp(ctx, email, appID)
	if err != nil || user == nil {
		// Don't reveal if user exists or not (security)
		log.Printf("[USER_SERVICE] User not found for email: %s, app_id: %s (returning success for security)", email, appID)
		return nil
	}

	log.Printf("[USER_SERVICE] User found: %s (ID: %s, AppID: %s)", user.Email, user.ID, user.AppID)

	// Generate password reset token (32 bytes = 64 hex chars)
	token, err := generateSecureToken(32)
	if err != nil {
		return errors.New("failed to generate reset token")
	}

	// Token expires in 1 hour
	tokenExpiry := time.Now().Add(1 * time.Hour)

	// Update user with reset token
	user.PasswordResetToken = &token
	user.PasswordResetTokenExpiresAt = &tokenExpiry
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return errors.New("failed to update reset token")
	}

	// Send password reset email
	if s.cfg.Email.Enabled && s.emailService != nil {
		log.Printf("[USER_SERVICE] Calling email service to send password reset email to %s", user.Email)
		if err := s.emailService.SendPasswordResetEmail(ctx, user.Email, user.FirstName, token); err != nil {
			// Log error but don't fail (user already has token in DB)
			log.Printf("[USER_SERVICE] ERROR: Failed to send password reset email to %s: %v", user.Email, err)
		} else {
			log.Printf("[USER_SERVICE] Password reset email sent successfully to %s", user.Email)
		}
	} else {
		log.Printf("[USER_SERVICE] Email service disabled or not configured (Enabled: %v, Service: %v)", s.cfg.Email.Enabled, s.emailService != nil)
	}

	return nil
}

// ResetPassword resets a user's password using the reset token
func (s *UserService) ResetPassword(ctx context.Context, token, newPassword string) error {
	// Find user by reset token
	user, err := s.userRepo.GetByPasswordResetToken(ctx, token)
	if err != nil || user == nil {
		return errors.New("invalid or expired reset token")
	}

	// Check if token is expired
	if user.PasswordResetTokenExpiresAt != nil && time.Now().After(*user.PasswordResetTokenExpiresAt) {
		return errors.New("reset token has expired")
	}

	// Hash new password
	passwordHash, err := hash.HashPassword(newPassword)
	if err != nil {
		return errors.New("failed to hash password")
	}

	// Update user: set new password and clear reset token
	user.PasswordHash = passwordHash
	user.PasswordResetToken = nil
	user.PasswordResetTokenExpiresAt = nil
	user.UpdatedAt = time.Now()

	if err := s.userRepo.Update(ctx, user); err != nil {
		return errors.New("failed to reset password")
	}

	// SECURITY: Invalidate all existing sessions AND blacklist all tokens
	// This forces re-login with the new password
	if s.authService != nil {
		if err := s.authService.InvalidateAllUserSessions(ctx, user.ID); err != nil {
			fmt.Printf("Warning: Failed to invalidate sessions and blacklist tokens for user %s: %v\n", user.ID, err)
		} else {
			fmt.Printf("All sessions and tokens invalidated for user %s after password reset\n", user.ID)
		}
	} else {
		// Fallback: just delete sessions if authService not set
		if err := s.sessionRepo.DeleteByUserID(ctx, user.ID); err != nil {
			fmt.Printf("Warning: Failed to invalidate sessions for user %s: %v\n", user.ID, err)
		}
	}

	// Send password changed confirmation email (async)
	if s.cfg.Email.Enabled && s.emailService != nil {
		go func() {
			emailCtx := context.Background()
			if err := s.emailService.SendPasswordChangedEmail(emailCtx, user.Email, user.FirstName); err != nil {
				fmt.Printf("Failed to send password changed email to %s: %v\n", user.Email, err)
			}
		}()
	}

	return nil
}

// List retrieves users with pagination and search
func (s *UserService) List(ctx context.Context, limit, offset int, search string) ([]*domain.User, int, error) {
	return s.userRepo.List(ctx, limit, offset, search)
}

// GetUserRolesAllApps retrieves all roles for a user across all applications
func (s *UserService) GetUserRolesAllApps(ctx context.Context, userID uuid.UUID) ([]string, error) {
	return s.userRepo.GetUserRolesAllApps(ctx, userID)
}

// SuperAdminExists checks if any super admin user exists
func (s *UserService) SuperAdminExists(ctx context.Context) (bool, error) {
	return s.userRepo.SuperAdminExists(ctx)
}

// CreateSuperAdmin creates a super admin user
func (s *UserService) CreateSuperAdmin(ctx context.Context, email, password, firstName, lastName string) (*domain.User, error) {
	// Check if user already exists
	existingUser, err := s.userRepo.GetByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Hash password
	passwordHash, err := hash.HashPassword(password)
	if err != nil {
		return nil, errors.New("failed to hash password")
	}

	// Create user
	user := &domain.User{
		ID:            uuid.New(),
		Email:         email,
		PasswordHash:  passwordHash,
		FirstName:     firstName,
		LastName:      lastName,
		Status:        domain.UserStatusActive,
		EmailVerified: true, // Super admin is auto-verified
		MFAEnabled:    false,
		FailedLogins:  0,
		IsSuperAdmin:  true, // Mark as super admin
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	// Save user to database
	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, errors.New("failed to create super admin user")
	}

	// Assign super_admin role
	superAdminRoleID := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	if err := s.userRepo.AssignRole(ctx, user.ID, superAdminRoleID); err != nil {
		return nil, errors.New("failed to assign super_admin role")
	}

	return user, nil
}

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
