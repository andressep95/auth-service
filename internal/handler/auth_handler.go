package handler

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
	"github.com/google/uuid"
)

type AuthHandler struct {
	authService   *service.AuthService
	oauthService  *service.OAuthService
	tenantService *service.TenantService
	appService    *service.AppService
	roleService   *service.RoleService
	validator     *validator.Validator
}

func NewAuthHandler(authService *service.AuthService, oauthService *service.OAuthService, validator *validator.Validator) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		oauthService: oauthService,
		validator:    validator,
	}
}

// SetServices sets additional services needed for some endpoints
func (h *AuthHandler) SetServices(tenantService *service.TenantService, appService *service.AppService, roleService *service.RoleService) {
	h.tenantService = tenantService
	h.appService = appService
	h.roleService = roleService
}

// Login handles user login with SECURE auto-detection
// POST /api/v1/auth/login
//
// SECURITY: app_id is ONLY resolved from Origin header (via CORS middleware)
// ⚠️ NO app_id accepted in form/query/body to prevent leakage attacks
//
// OAuth2 Flow (Authorization Code):
//   - Auto-detects app from Origin header
//   - Returns: HTTP 302 redirect to redirect_uri?code=xxx&state=xxx
//
// Direct Token Flow (backward compatible):
//   - For programmatic API access only
//   - Returns: JSON with access_token and refresh_token
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	log.Printf("[AUTH_HANDLER] Login request received")

	var req service.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[AUTH_HANDLER] Body parser error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	log.Printf("[AUTH_HANDLER] Parsed request - Email: %s", req.Email)

	// SECURITY: Get app_id ONLY from auto-detection
	var appID uuid.UUID
	var app *domain.App

	// Try from CORS middleware first (cross-origin requests)
	if autoAppID := c.Locals("auto_detected_app_id"); autoAppID != nil {
		appIDStr := autoAppID.(string)
		var parseErr error
		appID, parseErr = uuid.Parse(appIDStr)
		if parseErr != nil {
			log.Printf("[AUTH_HANDLER] Invalid auto-detected app_id: %s", appIDStr)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied: Invalid application",
			})
		}

		log.Printf("[AUTH_HANDLER] Using CORS auto-detected app_id: %s", appID)

		// Get full app details
		if autoApp := c.Locals("auto_detected_app"); autoApp != nil {
			app = autoApp.(*domain.App)
			log.Printf("[AUTH_HANDLER] App: %s", app.Name)
		}
	} else {
		// CORS didn't detect (same-origin request), try manual detection
		origin := getOriginFromRequest(c)
		if origin == "" {
			log.Printf("[AUTH_HANDLER] Could not determine origin")
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied: Could not determine origin",
			})
		}

		log.Printf("[AUTH_HANDLER] Auto-detecting app from origin: %s", origin)

		if h.appService == nil {
			log.Printf("[AUTH_HANDLER] appService not initialized")
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Internal server error: app service not configured",
			})
		}

		resolution, err := h.appService.ResolveAppFromOrigin(c.Context(), origin)
		if err != nil {
			log.Printf("[AUTH_HANDLER] Failed to resolve app from origin %s: %v", origin, err)
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied: Origin not registered. Please access from registered web application.",
			})
		}

		app = resolution.App
		appID = app.ID
		log.Printf("[AUTH_HANDLER] App auto-detected: %s (ID: %s)", app.Name, appID)
	}

	// Override req.AppID with secure auto-detected value
	req.AppID = appID.String()

	if err := h.validator.Validate(req); err != nil {
		log.Printf("[AUTH_HANDLER] Validation error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// OAuth2 parameters - auto-generated from app configuration
	redirectURI := c.FormValue("redirect_uri")
	if redirectURI == "" {
		redirectURI = req.RedirectURI
	}

	state := c.FormValue("state")
	if state == "" {
		state = req.State
	}

	scope := c.FormValue("scope")
	if scope == "" {
		scope = req.Scope
	}

	// Auto-complete redirect_uri from app configuration
	if redirectURI == "" && app != nil {
		origin := c.Get("Origin")
		if origin != "" {
			// Find matching redirect_uri for this origin
			for _, uri := range app.RedirectURIs {
				if strings.HasPrefix(uri, origin) {
					redirectURI = uri
					log.Printf("[AUTH_HANDLER] Auto-completed redirect_uri: %s", redirectURI)
					break
				}
			}

			// Default to first redirect_uri if still empty
			if redirectURI == "" && len(app.RedirectURIs) > 0 {
				redirectURI = app.RedirectURIs[0]
				log.Printf("[AUTH_HANDLER] Using first redirect_uri: %s", redirectURI)
			}
		}
	}

	responseType := c.FormValue("response_type")
	if responseType == "" {
		responseType = req.ResponseType
	}

	// Auto-set response_type to "code" for OAuth2 flow
	if responseType == "" && redirectURI != "" {
		responseType = "code"
	}

	// Determine flow: OAuth2 Authorization Code or Direct Token
	isOAuth2Flow := redirectURI != "" && responseType == "code"

	log.Printf("[AUTH_HANDLER] Flow detected - OAuth2: %v, RedirectURI: %s, AppID: %s", isOAuth2Flow, redirectURI, appID)

	// Step 1: Authenticate user (common for both flows)
	log.Printf("[AUTH_HANDLER] Validation passed, calling auth service...")
	resp, err := h.authService.Login(c.Context(), req)
	if err != nil {
		log.Printf("[AUTH_HANDLER] Login failed: %v", err)

		// If OAuth2 flow, redirect with error
		if isOAuth2Flow {
			errorURL, _ := url.Parse(redirectURI)
			query := errorURL.Query()
			query.Set("error", "access_denied")
			query.Set("error_description", err.Error())
			if state != "" {
				query.Set("state", state)
			}
			errorURL.RawQuery = query.Encode()
			return c.Redirect(errorURL.String(), fiber.StatusFound)
		}

		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	log.Printf("[AUTH_HANDLER] Login successful for user: %s", req.Email)

	// Step 2: Handle flow-specific response
	if isOAuth2Flow {
		// OAuth2 Authorization Code Flow
		log.Printf("[AUTH_HANDLER] OAuth2 flow - generating authorization code")

		// Validate redirect_uri against app whitelist
		appID, err := uuid.Parse(req.AppID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid app_id",
			})
		}

		if err := h.oauthService.ValidateRedirectURI(c.Context(), appID, redirectURI); err != nil {
			log.Printf("[AUTH_HANDLER] Redirect URI validation failed: %v", err)
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": fmt.Sprintf("Invalid redirect_uri: %v", err),
			})
		}

		// Generate authorization code
		var statePtr, scopePtr *string
		if state != "" {
			statePtr = &state
		}
		if scope != "" {
			scopePtr = &scope
		}

		code, err := h.oauthService.GenerateAuthorizationCode(
			c.Context(),
			appID,
			resp.User.ID,
			redirectURI,
			statePtr,
			scopePtr,
		)
		if err != nil {
			log.Printf("[AUTH_HANDLER] Failed to generate authorization code: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to generate authorization code",
			})
		}

		// Build redirect URL with code and state
		redirectURL, err := url.Parse(redirectURI)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "Invalid redirect_uri format",
			})
		}

		query := redirectURL.Query()
		query.Set("code", code)
		if state != "" {
			query.Set("state", state)
		}
		redirectURL.RawQuery = query.Encode()

		log.Printf("[AUTH_HANDLER] Redirecting to: %s", redirectURL.String())
		return c.Redirect(redirectURL.String(), fiber.StatusFound)
	}

	// Direct Token Flow (backward compatible)
	log.Printf("[AUTH_HANDLER] Direct token flow - returning tokens in JSON")
	return c.Status(fiber.StatusOK).JSON(resp)
}

// RefreshToken handles token refresh
// POST /api/v1/auth/refresh
func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Validate(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	tokens, err := h.authService.RefreshToken(c.Context(), req.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(tokens)
}

// Logout handles user logout
// POST /api/v1/auth/logout
func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if err := h.validator.Validate(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Extract access token from Authorization header (optional)
	// If provided, it will be blacklisted immediately
	accessToken := ""
	authHeader := c.Get("Authorization")
	if authHeader != "" {
		// Check if it's a Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			accessToken = parts[1]
		}
	}

	if err := h.authService.Logout(c.Context(), req.RefreshToken, accessToken); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Logged out successfully",
	})
}

// RegisterWithInvitation handles user registration with invitation token
// POST /api/v1/auth/register-with-invitation
func (h *AuthHandler) RegisterWithInvitation(c *fiber.Ctx) error {
	var req service.RegisterWithInvitationRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	if err := h.validator.Validate(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	resp, redirectURL, err := h.authService.RegisterWithInvitation(
		c.Context(),
		req,
		h.tenantService,
		h.appService,
	)

	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	// Return response with redirect URL
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message":      "Registration successful",
		"user":         resp.User,
		"tokens":       resp.Tokens,
		"redirect_url": redirectURL,
	})
}
