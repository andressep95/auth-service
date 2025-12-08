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
	BaseURL string        // URL of the email service API endpoint
	Timeout time.Duration // HTTP request timeout
}

// EmailMetrics holds metrics for monitoring
type EmailMetrics struct {
	Sent   int64
	Failed int64
}
