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
	client     *http.Client
	serviceURL string
	config     *EmailConfig
}

// CloudCentinelEmailRequest represents the request body for CloudCentinel email service
type CloudCentinelEmailRequest struct {
	Type  string `json:"type"`            // verification, password_reset, welcome, password_changed
	To    string `json:"to"`              // recipient email
	Name  string `json:"name"`            // recipient name
	Token string `json:"token,omitempty"` // token for verification/reset (optional)
}

// CloudCentinelEmailResponse represents the response from CloudCentinel email service
type CloudCentinelEmailResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// NewCloudCentinelEmailService creates a new CloudCentinel email service
func NewCloudCentinelEmailService(config *EmailConfig) (*CloudCentinelEmailService, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("email service URL is required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &CloudCentinelEmailService{
		client: &http.Client{
			Timeout: timeout,
		},
		serviceURL: config.BaseURL,
		config:     config,
	}, nil
}

// sendEmail is a helper method to send email requests to CloudCentinel service
func (s *CloudCentinelEmailService) sendEmail(ctx context.Context, req *CloudCentinelEmailRequest) error {
	// Marshal request body
	jsonData, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.serviceURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send email request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK {
		var errorResp CloudCentinelEmailResponse
		if err := json.Unmarshal(body, &errorResp); err != nil {
			return fmt.Errorf("email service returned status %d: %s", resp.StatusCode, string(body))
		}
		return fmt.Errorf("email service error: %s", errorResp.Error)
	}

	// Parse success response
	var successResp CloudCentinelEmailResponse
	if err := json.Unmarshal(body, &successResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !successResp.Success {
		return fmt.Errorf("email service returned success=false: %s", successResp.Error)
	}

	return nil
}

// SendVerificationEmail sends an email verification link to the user
func (s *CloudCentinelEmailService) SendVerificationEmail(ctx context.Context, to, name, token string) error {
	req := &CloudCentinelEmailRequest{
		Type:  "verification",
		To:    to,
		Name:  name,
		Token: token,
	}

	if err := s.sendEmail(ctx, req); err != nil {
		log.Printf("Failed to send verification email to %s: %v", to, err)
		return fmt.Errorf("failed to send verification email: %w", err)
	}

	log.Printf("Verification email sent successfully to %s", to)
	return nil
}

// SendPasswordResetEmail sends a password reset link to the user
func (s *CloudCentinelEmailService) SendPasswordResetEmail(ctx context.Context, to, name, token string) error {
	req := &CloudCentinelEmailRequest{
		Type:  "password_reset",
		To:    to,
		Name:  name,
		Token: token,
	}

	if err := s.sendEmail(ctx, req); err != nil {
		log.Printf("Failed to send password reset email to %s: %v", to, err)
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	log.Printf("Password reset email sent successfully to %s", to)
	return nil
}

// SendWelcomeEmail sends a welcome email to newly verified users
func (s *CloudCentinelEmailService) SendWelcomeEmail(ctx context.Context, to, name string) error {
	req := &CloudCentinelEmailRequest{
		Type: "welcome",
		To:   to,
		Name: name,
	}

	if err := s.sendEmail(ctx, req); err != nil {
		log.Printf("Failed to send welcome email to %s: %v", to, err)
		return fmt.Errorf("failed to send welcome email: %w", err)
	}

	log.Printf("Welcome email sent successfully to %s", to)
	return nil
}

// SendPasswordChangedEmail sends a notification when password is changed
func (s *CloudCentinelEmailService) SendPasswordChangedEmail(ctx context.Context, to, name string) error {
	req := &CloudCentinelEmailRequest{
		Type: "password_changed",
		To:   to,
		Name: name,
	}

	if err := s.sendEmail(ctx, req); err != nil {
		log.Printf("Failed to send password changed email to %s: %v", to, err)
		return fmt.Errorf("failed to send password changed email: %w", err)
	}

	log.Printf("Password changed email sent successfully to %s", to)
	return nil
}
