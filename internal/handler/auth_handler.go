package handler

import (
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
)

type AuthHandler struct {
	authService *service.AuthService
	validator   *validator.Validator
}

func NewAuthHandler(authService *service.AuthService, validator *validator.Validator) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validator:   validator,
	}
}

// Login handles user login
// POST /api/v1/auth/login
func (h *AuthHandler) Login(c *fiber.Ctx) error {
	log.Printf("[AUTH_HANDLER] Login request received")

	var req service.LoginRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[AUTH_HANDLER] Body parser error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	log.Printf("[AUTH_HANDLER] Parsed request - Email: %s, AppID: %s", req.Email, req.AppID)

	if err := h.validator.Validate(req); err != nil {
		log.Printf("[AUTH_HANDLER] Validation error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	log.Printf("[AUTH_HANDLER] Validation passed, calling auth service...")
	resp, err := h.authService.Login(c.Context(), req)
	if err != nil {
		log.Printf("[AUTH_HANDLER] Login failed: %v", err)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	log.Printf("[AUTH_HANDLER] Login successful for user: %s", req.Email)
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
