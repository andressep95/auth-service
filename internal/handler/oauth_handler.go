package handler

import (
	"log"

	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type OAuthHandler struct {
	oauthService *service.OAuthService
	authService  *service.AuthService
	roleService  *service.RoleService
	validator    *validator.Validator
}

func NewOAuthHandler(
	oauthService *service.OAuthService,
	authService *service.AuthService,
	roleService *service.RoleService,
	validator *validator.Validator,
) *OAuthHandler {
	return &OAuthHandler{
		oauthService: oauthService,
		authService:  authService,
		roleService:  roleService,
		validator:    validator,
	}
}

// TokenRequest represents the OAuth2 token request
type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type" validate:"required"`       // Must be "authorization_code"
	Code         string `json:"code" form:"code" validate:"required"`                   // Authorization code
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri" validate:"required"`   // Must match the one used in authorization
	ClientID     string `json:"client_id" form:"client_id" validate:"required,uuid"`    // App ID
	ClientSecret string `json:"client_secret" form:"client_secret"`                     // Optional for public clients
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`                     // PKCE code verifier (optional)
}

// TokenResponse represents the OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

// Token handles the OAuth2 token exchange endpoint
// POST /oauth/token
//
// Exchanges an authorization code for access and refresh tokens
// Implements RFC 6749 Section 4.1.3 (Access Token Request)
func (h *OAuthHandler) Token(c *fiber.Ctx) error {
	log.Printf("[OAUTH_HANDLER] Token exchange request received")

	var req TokenRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[OAUTH_HANDLER] Body parser error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": "Invalid request body",
		})
	}

	log.Printf("[OAUTH_HANDLER] Token request - GrantType: %s, ClientID: %s", req.GrantType, req.ClientID)

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		log.Printf("[OAUTH_HANDLER] Validation error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
	}

	// Only support authorization_code grant type for now
	if req.GrantType != "authorization_code" {
		log.Printf("[OAUTH_HANDLER] Unsupported grant type: %s", req.GrantType)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code grant type is supported",
		})
	}

	// Exchange authorization code for tokens
	authCode, err := h.oauthService.ExchangeCodeForTokens(c.Context(), req.Code, req.RedirectURI)
	if err != nil {
		log.Printf("[OAUTH_HANDLER] Code exchange failed: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
	}

	// Validate client_id matches the authorization code
	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "Invalid client_id format",
		})
	}

	if authCode.AppID != clientID {
		log.Printf("[OAUTH_HANDLER] Client ID mismatch - Expected: %s, Got: %s", authCode.AppID, clientID)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":             "invalid_client",
			"error_description": "client_id does not match authorization code",
		})
	}

	// TODO: Validate PKCE code_verifier if code_challenge was provided
	// if authCode.CodeChallenge != nil && req.CodeVerifier == "" {
	//     return error - PKCE required
	// }

	// Generate JWT tokens for the user
	log.Printf("[OAUTH_HANDLER] Generating tokens for user: %s", authCode.UserID)

	// Get user roles for JWT claims
	roles, err := h.roleService.GetUserRoleNames(c.Context(), authCode.UserID)
	if err != nil {
		log.Printf("[OAUTH_HANDLER] Failed to get user roles: %v", err)
		roles = []string{} // Continue with empty roles
	}

	// Generate access token (15 minutes)
	accessToken, err := h.authService.GenerateAccessToken(authCode.UserID, authCode.AppID, roles)
	if err != nil {
		log.Printf("[OAUTH_HANDLER] Failed to generate access token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Failed to generate access token",
		})
	}

	// Generate refresh token (7 days) and create session
	refreshToken, err := h.authService.GenerateRefreshToken(c.Context(), authCode.UserID, authCode.AppID, c.Get("User-Agent"), c.IP())
	if err != nil {
		log.Printf("[OAUTH_HANDLER] Failed to generate refresh token: %v", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error":             "server_error",
			"error_description": "Failed to generate refresh token",
		})
	}

	// Build response
	scope := ""
	if authCode.Scope != nil {
		scope = *authCode.Scope
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes in seconds
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	log.Printf("[OAUTH_HANDLER] Token exchange successful for user: %s", authCode.UserID)
	return c.Status(fiber.StatusOK).JSON(response)
}
