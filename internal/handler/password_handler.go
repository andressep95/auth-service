package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
)

type PasswordHandler struct {
	authService *service.AuthService
	validator   *validator.Validator
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required,min=8"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

func NewPasswordHandler(authService *service.AuthService, validator *validator.Validator) *PasswordHandler {
	return &PasswordHandler{
		authService: authService,
		validator:   validator,
	}
}

// ChangePassword handles password change requests
func (h *PasswordHandler) ChangePassword(c *fiber.Ctx) error {
	// Get user ID from context (set by auth middleware)
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "unauthorized",
		})
	}

	// Parse request
	var req ChangePasswordRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid request body",
		})
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Validate new password is different from old
	if req.OldPassword == req.NewPassword {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "new password must be different from old password",
		})
	}

	// Change password
	if err := h.authService.ChangePassword(c.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		if err == service.ErrInvalidCredentials {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid old password",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "failed to change password",
		})
	}

	return c.JSON(fiber.Map{
		"message": "password changed successfully, all sessions have been invalidated",
	})
}
