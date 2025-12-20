package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// CloudCentinelEmailService implements EmailService using CloudCentinel Email Service
type CloudCentinelEmailService struct {
	client               *http.Client
	serviceURL           string
	verificationBaseURL  string
	passwordResetBaseURL string
	config               *EmailConfig
}

// CustomEmailRequest represents the request body for custom HTML email (using /send-custom endpoint)
type CustomEmailRequest struct {
	To      string `json:"to"`      // recipient email
	Subject string `json:"subject"` // email subject
	HTML    string `json:"html"`    // custom HTML content
}

// EmailResponse represents the response from email service
type EmailResponse struct {
	Status string `json:"status"` // "sent"
}

// NewCloudCentinelEmailService creates a new CloudCentinel email service
func NewCloudCentinelEmailService(config *EmailConfig) (*CloudCentinelEmailService, error) {
	if config.ServiceURL == "" {
		return nil, fmt.Errorf("email service URL is required")
	}

	if config.VerificationBaseURL == "" {
		return nil, fmt.Errorf("email verification base URL is required")
	}

	if config.PasswordResetBaseURL == "" {
		return nil, fmt.Errorf("email password reset base URL is required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	log.Printf("[EMAIL_INIT] Initializing CloudCentinel email service with custom HTML templates")
	log.Printf("[EMAIL_INIT] Service URL: %s", config.ServiceURL)
	log.Printf("[EMAIL_INIT] Verification Base URL: %s", config.VerificationBaseURL)
	log.Printf("[EMAIL_INIT] Password Reset Base URL: %s", config.PasswordResetBaseURL)
	log.Printf("[EMAIL_INIT] Timeout: %v", timeout)

	return &CloudCentinelEmailService{
		client: &http.Client{
			Timeout: timeout,
		},
		serviceURL:           config.ServiceURL,
		verificationBaseURL:  config.VerificationBaseURL,
		passwordResetBaseURL: config.PasswordResetBaseURL,
		config:               config,
	}, nil
}

// sendCustomEmail is a helper method to send custom HTML email requests to CloudCentinel service
func (s *CloudCentinelEmailService) sendCustomEmail(ctx context.Context, to, subject, htmlContent string) error {
	// Create custom email request
	req := &CustomEmailRequest{
		To:      to,
		Subject: subject,
		HTML:    htmlContent,
	}

	// Marshal request body
	jsonData, err := json.Marshal(req)
	if err != nil {
		log.Printf("[EMAIL] ERROR: Failed to marshal request: %v", err)
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("[EMAIL] ========== EMAIL REQUEST START ==========")
	log.Printf("[EMAIL] To: %s", req.To)
	log.Printf("[EMAIL] Subject: %s", req.Subject)
	log.Printf("[EMAIL] HTML Length: %d bytes", len(req.HTML))
	log.Printf("[EMAIL] Target URL: %s", s.serviceURL)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.serviceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("[EMAIL] ERROR: Failed to create HTTP request: %v", err)
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	log.Printf("[EMAIL] Request Method: %s", httpReq.Method)
	log.Printf("[EMAIL] Request URL (full): %s", httpReq.URL.String())

	// Send request
	log.Printf("[EMAIL] Sending HTTP request now...")
	startTime := time.Now()
	resp, err := s.client.Do(httpReq)
	elapsed := time.Since(startTime)

	if err != nil {
		log.Printf("[EMAIL] ERROR: Failed to send email request after %v: %v", elapsed, err)
		return fmt.Errorf("failed to send email request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("[EMAIL] Received response in %v - Status: %d", elapsed, resp.StatusCode)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[EMAIL] ERROR: Failed to read response body: %v", err)
		return fmt.Errorf("failed to read response body: %w", err)
	}

	log.Printf("[EMAIL] Response body: %s", string(body))

	// Check status code
	if resp.StatusCode != http.StatusOK {
		log.Printf("[EMAIL] ERROR: Non-OK status code %d", resp.StatusCode)
		return fmt.Errorf("email service returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse success response
	var successResp EmailResponse
	if err := json.Unmarshal(body, &successResp); err != nil {
		log.Printf("[EMAIL] ERROR: Failed to parse success response: %v", err)
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if successResp.Status != "sent" {
		log.Printf("[EMAIL] ERROR: Email service returned unexpected status: %s", successResp.Status)
		return fmt.Errorf("email service returned unexpected status: %s", successResp.Status)
	}

	log.Printf("[EMAIL] SUCCESS: Email sent successfully")
	log.Printf("[EMAIL] ========== EMAIL REQUEST END ==========")
	return nil
}

// SendVerificationEmail sends an email verification link to the user
// Uses the configured VerificationBaseURL from EmailConfig
func (s *CloudCentinelEmailService) SendVerificationEmail(ctx context.Context, to, name, token string) error {
	return s.SendVerificationEmailWithURL(ctx, to, name, token, s.verificationBaseURL)
}

// SendVerificationEmailWithURL sends an email verification link with custom base URL
// baseURL should be the full URL path (e.g., "http://localhost:8080/auth/verify-email")
func (s *CloudCentinelEmailService) SendVerificationEmailWithURL(ctx context.Context, to, name, token, baseURL string) error {
	// Build verification URL with query parameter
	verificationURL := fmt.Sprintf("%s?token=%s", baseURL, token)

	// Generate HTML content using template
	htmlContent := VerificationEmailTemplate(name, verificationURL)

	// Send email with custom HTML
	subject := "Verify Your Email Address"
	if err := s.sendCustomEmail(ctx, to, subject, htmlContent); err != nil {
		log.Printf("Failed to send verification email to %s: %v", to, err)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	log.Printf("Verification email sent successfully to %s (baseURL: %s)", to, baseURL)
	return nil
}

// SendPasswordResetEmail sends a password reset link to the user
// Uses the configured PasswordResetBaseURL from EmailConfig
func (s *CloudCentinelEmailService) SendPasswordResetEmail(ctx context.Context, to, name, token string) error {
	return s.SendPasswordResetEmailWithURL(ctx, to, name, token, s.passwordResetBaseURL)
}

// SendPasswordResetEmailWithURL sends a password reset link with custom base URL
// baseURL should be the full URL path (e.g., "http://localhost:8080/auth/reset-password")
func (s *CloudCentinelEmailService) SendPasswordResetEmailWithURL(ctx context.Context, to, name, token, baseURL string) error {
	// Build password reset URL with query parameter
	resetURL := fmt.Sprintf("%s?token=%s", baseURL, token)

	// Generate HTML content using template
	htmlContent := PasswordResetEmailTemplate(name, resetURL)

	// Send email with custom HTML
	subject := "Reset Your Password"
	if err := s.sendCustomEmail(ctx, to, subject, htmlContent); err != nil {
		log.Printf("Failed to send password reset email to %s: %v", to, err)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	log.Printf("Password reset email sent successfully to %s (baseURL: %s)", to, baseURL)
	return nil
}

// SendWelcomeEmail sends a welcome email to newly verified users
func (s *CloudCentinelEmailService) SendWelcomeEmail(ctx context.Context, to, name string) error {
	// Generate HTML content using template
	htmlContent := WelcomeEmailTemplate(name)

	// Send email with custom HTML
	subject := "Welcome to Our Platform!"
	if err := s.sendCustomEmail(ctx, to, subject, htmlContent); err != nil {
		log.Printf("Failed to send welcome email to %s: %v", to, err)
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	log.Printf("Welcome email sent successfully to %s", to)
	return nil
}

// SendPasswordChangedEmail sends a notification when password is changed
func (s *CloudCentinelEmailService) SendPasswordChangedEmail(ctx context.Context, to, name string) error {
	// Generate HTML content using template
	htmlContent := PasswordChangedEmailTemplate(name)

	// Send email with custom HTML
	subject := "Your Password Has Been Changed"
	if err := s.sendCustomEmail(ctx, to, subject, htmlContent); err != nil {
		log.Printf("Failed to send password changed email to %s: %v", to, err)
		return fmt.Errorf("failed to send password changed email: %w", err)
	}

	log.Printf("Password changed email sent successfully to %s", to)
	return nil
}
