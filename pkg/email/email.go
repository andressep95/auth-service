package email

import (
	"context"
	"time"
)

// EmailService defines the interface for sending emails
type EmailService interface {
	// SendVerificationEmail sends an email verification link to the user
	// Uses the configured VerificationBaseURL from EmailConfig
	SendVerificationEmail(ctx context.Context, to, name, token string) error

	// SendVerificationEmailWithURL sends an email verification link with custom base URL
	// baseURL should be the full URL path (e.g., "http://localhost:8080/auth/verify-email")
	SendVerificationEmailWithURL(ctx context.Context, to, name, token, baseURL string) error

	// SendPasswordResetEmail sends a password reset link to the user
	// Uses the configured PasswordResetBaseURL from EmailConfig
	SendPasswordResetEmail(ctx context.Context, to, name, token string) error

	// SendPasswordResetEmailWithURL sends a password reset link with custom base URL
	// baseURL should be the full URL path (e.g., "http://localhost:8080/auth/reset-password")
	SendPasswordResetEmailWithURL(ctx context.Context, to, name, token, baseURL string) error

	// SendWelcomeEmail sends a welcome email to newly verified users
	SendWelcomeEmail(ctx context.Context, to, name string) error

	// SendPasswordChangedEmail sends a notification when password is changed
	SendPasswordChangedEmail(ctx context.Context, to, name string) error
}

// EmailRequest represents a generic email request
type EmailRequest struct {
	To          []string
	From        string
	Subject     string
	TextContent string
	HTMLContent string
	ReplyTo     string
}

// EmailConfig holds email service configuration
type EmailConfig struct {
	ServiceURL           string        // URL of the email service API endpoint (should point to /send-custom)
	Timeout              time.Duration // HTTP request timeout
	VerificationBaseURL  string        // Base URL for email verification links
	PasswordResetBaseURL string        // Base URL for password reset links
}

// EmailMetrics holds metrics for monitoring
type EmailMetrics struct {
	Sent   int64
	Failed int64
}
