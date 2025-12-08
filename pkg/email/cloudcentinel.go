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

	log.Printf("[EMAIL_INIT] Initializing CloudCentinel email service")
	log.Printf("[EMAIL_INIT] Service URL: %s", config.BaseURL)
	log.Printf("[EMAIL_INIT] Timeout: %v", timeout)

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
		log.Printf("[EMAIL] ERROR: Failed to marshal request: %v", err)
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	log.Printf("[EMAIL] ========== EMAIL REQUEST START ==========")
	log.Printf("[EMAIL] Type: %s", req.Type)
	log.Printf("[EMAIL] To: %s", req.To)
	log.Printf("[EMAIL] Name: %s", req.Name)
	log.Printf("[EMAIL] Token: %s", req.Token)
	log.Printf("[EMAIL] Target URL: %s", s.serviceURL)
	log.Printf("[EMAIL] Request body: %s", string(jsonData))

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
	log.Printf("[EMAIL] Request Host: %s", httpReq.Host)
	log.Printf("[EMAIL] Request Headers: %v", httpReq.Header)

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
		var errorResp CloudCentinelEmailResponse
		if err := json.Unmarshal(body, &errorResp); err != nil {
			log.Printf("[EMAIL] ERROR: Failed to parse error response: %v", err)
			return fmt.Errorf("email service returned status %d: %s", resp.StatusCode, string(body))
		}
		log.Printf("[EMAIL] ERROR: Email service error: %s", errorResp.Error)
		return fmt.Errorf("email service error: %s", errorResp.Error)
	}

	// Parse success response
	var successResp CloudCentinelEmailResponse
	if err := json.Unmarshal(body, &successResp); err != nil {
		log.Printf("[EMAIL] ERROR: Failed to parse success response: %v", err)
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !successResp.Success {
		log.Printf("[EMAIL] ERROR: Email service returned success=false: %s", successResp.Error)
		return fmt.Errorf("email service returned success=false: %s", successResp.Error)
	}

	log.Printf("[EMAIL] SUCCESS: Email sent successfully")
	log.Printf("[EMAIL] ========== EMAIL REQUEST END ==========")
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
