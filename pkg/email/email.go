package email

import (
	"context"
	"time"
)

// EmailService defines the interface for sending emails
type EmailService interface {
	// SendVerificationEmail sends an email verification link to the user
	SendVerificationEmail(ctx context.Context, to, name, token string) error

	// SendPasswordResetEmail sends a password reset link to the user
	SendPasswordResetEmail(ctx context.Context, to, name, token string) error

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
	Provider        string        // resend, sendgrid, etc.
	APIKey          string        // API key for the provider
	FromEmail       string        // Default from email
	FromName        string        // Default from name
	BaseURL         string        // Base URL for email links (e.g., https://app.example.com)
	Timeout         time.Duration // Request timeout
	VerificationURL string        // URL template for verification links
	ResetURL        string        // URL template for password reset links
}

// EmailMetrics holds metrics for monitoring
type EmailMetrics struct {
	Sent   int64
	Failed int64
}
