package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/config"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/repository"
	"github.com/andressep95/auth-service/pkg/email"
	"github.com/andressep95/auth-service/pkg/hash"
)

type UserService struct {
	userRepo     repository.UserRepository
	sessionRepo  repository.SessionRepository
	authService  *AuthService
	emailService email.EmailService
	cfg          *config.Config
}

type RegisterRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
}

func NewUserService(userRepo repository.UserRepository, sessionRepo repository.SessionRepository, emailService email.EmailService, cfg *config.Config) *UserService {
	return &UserService{
		userRepo:     userRepo,
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
	// Check if user already exists
	existingUser, err := s.userRepo.GetByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, errors.New("user with this email already exists")
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
func (s *UserService) RequestPasswordReset(ctx context.Context, email string) error {
	// Get user by email
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil || user == nil {
		// Don't reveal if user exists or not (security)
		return nil
	}

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
		if err := s.emailService.SendPasswordResetEmail(ctx, user.Email, user.FirstName, token); err != nil {
			// Log error but don't fail (user already has token in DB)
			fmt.Printf("Failed to send password reset email to %s: %v\n", user.Email, err)
		}
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

// generateSecureToken generates a cryptographically secure random token
func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
