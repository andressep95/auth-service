package email

import (
	"context"
	"fmt"
	"log"

	"github.com/resend/resend-go/v2"
)

// ResendEmailService implements EmailService using Resend
type ResendEmailService struct {
	client *resend.Client
	config *EmailConfig
}

// NewResendEmailService creates a new Resend email service
func NewResendEmailService(config *EmailConfig) (*ResendEmailService, error) {
	if config.APIKey == "" {
		return nil, fmt.Errorf("resend API key is required")
	}

	if config.FromEmail == "" {
		return nil, fmt.Errorf("from email is required")
	}

	client := resend.NewClient(config.APIKey)

	return &ResendEmailService{
		client: client,
		config: config,
	}, nil
}

// SendVerificationEmail sends an email verification link to the user
func (s *ResendEmailService) SendVerificationEmail(ctx context.Context, to, name, token string) error {
	verificationURL := fmt.Sprintf("%s?token=%s", s.config.VerificationURL, token)
	htmlContent := VerificationEmailTemplate(name, verificationURL)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail),
		To:      []string{to},
		Subject: "Verify Your Email Address",
		Html:    htmlContent,
	}

	sent, err := s.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		log.Printf("Failed to send verification email to %s: %v", to, err)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	log.Printf("Verification email sent successfully to %s (ID: %s)", to, sent.Id)
	return nil
}

// SendPasswordResetEmail sends a password reset link to the user
func (s *ResendEmailService) SendPasswordResetEmail(ctx context.Context, to, name, token string) error {
	resetURL := fmt.Sprintf("%s?token=%s", s.config.ResetURL, token)
	htmlContent := PasswordResetEmailTemplate(name, resetURL)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail),
		To:      []string{to},
		Subject: "Reset Your Password",
		Html:    htmlContent,
	}

	sent, err := s.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		log.Printf("Failed to send password reset email to %s: %v", to, err)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	log.Printf("Password reset email sent successfully to %s (ID: %s)", to, sent.Id)
	return nil
}

// SendWelcomeEmail sends a welcome email to newly verified users
func (s *ResendEmailService) SendWelcomeEmail(ctx context.Context, to, name string) error {
	htmlContent := WelcomeEmailTemplate(name)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail),
		To:      []string{to},
		Subject: "Welcome to Auth Service!",
		Html:    htmlContent,
	}

	sent, err := s.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		log.Printf("Failed to send welcome email to %s: %v", to, err)
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	log.Printf("Welcome email sent successfully to %s (ID: %s)", to, sent.Id)
	return nil
}

// SendPasswordChangedEmail sends a notification when password is changed
func (s *ResendEmailService) SendPasswordChangedEmail(ctx context.Context, to, name string) error {
	htmlContent := PasswordChangedEmailTemplate(name)

	params := &resend.SendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromEmail),
		To:      []string{to},
		Subject: "Password Changed Successfully",
		Html:    htmlContent,
	}

	sent, err := s.client.Emails.SendWithContext(ctx, params)
	if err != nil {
		log.Printf("Failed to send password changed email to %s: %v", to, err)
		return fmt.Errorf("failed to send password changed email: %w", err)
	}

	log.Printf("Password changed email sent successfully to %s (ID: %s)", to, sent.Id)
	return nil
}
