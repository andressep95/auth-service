package handler

import (
	"log"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type UserHandler struct {
	userService *service.UserService
	validator   *validator.Validator
}

func NewUserHandler(userService *service.UserService, validator *validator.Validator) *UserHandler {
	return &UserHandler{
		userService: userService,
		validator:   validator,
	}
}

// Register handles user registration
// POST /api/v1/auth/register
func (h *UserHandler) Register(c *fiber.Ctx) error {
	// Log raw body for debugging
	body := c.Body()
	log.Printf("[USER_HANDLER] Raw body (len=%d): %s", len(body), string(body))
	log.Printf("[USER_HANDLER] Content-Type: %s", c.Get("Content-Type"))

	var req service.RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		log.Printf("[USER_HANDLER] BodyParser error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body: " + err.Error(),
		})
	}

	log.Printf("[USER_HANDLER] Register request parsed: AppID=%s, Email=%s, FirstName=%s, LastName=%s",
		req.AppID, req.Email, req.FirstName, req.LastName)

	if err := h.validator.Validate(req); err != nil {
		log.Printf("[USER_HANDLER] Validation error: %v", err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	user, err := h.userService.Register(c.Context(), req)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
		"user":    user,
	})
}

// GetMe returns the current user's profile
// GET /api/v1/users/me (protected route)
func (h *UserHandler) GetMe(c *fiber.Ctx) error {
	// Extract user ID from fiber.Locals (set by auth middleware)
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	user, err := h.userService.GetByID(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.Status(fiber.StatusOK).JSON(user)
}

// VerifyEmail handles email verification
// POST /api/v1/auth/verify-email
func (h *UserHandler) VerifyEmail(c *fiber.Ctx) error {
	var req struct {
		Token string `json:"token" validate:"required"`
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

	if err := h.userService.VerifyEmail(c.Context(), req.Token); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Email verified successfully",
	})
}

// ResendVerificationEmail handles resending verification email
// POST /api/v1/auth/resend-verification
func (h *UserHandler) ResendVerificationEmail(c *fiber.Ctx) error {
	var req struct {
		Email string `json:"email" validate:"required,email"`
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

	if err := h.userService.ResendVerificationEmail(c.Context(), req.Email); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Verification email sent successfully",
	})
}

// ForgotPassword handles password reset request
// POST /api/v1/auth/forgot-password
func (h *UserHandler) ForgotPassword(c *fiber.Ctx) error {
	var req struct {
		Email string `json:"email" validate:"required,email"`
		AppID string `json:"app_id" validate:"omitempty,uuid"` // Optional, defaults to frontend app
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

	// Use default app_id if not provided
	appID := req.AppID
	if appID == "" {
		appID = "7057e69d-818b-45db-b39b-9d1c84aca142"
	}

	if err := h.userService.RequestPasswordReset(c.Context(), req.Email, appID); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Always return success to avoid user enumeration
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "If the email exists, a password reset link has been sent",
	})
}

// ResetPassword handles password reset with token
// POST /api/v1/auth/reset-password
func (h *UserHandler) ResetPassword(c *fiber.Ctx) error {
	var req struct {
		Token       string `json:"token" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=8"`
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

	if err := h.userService.ResetPassword(c.Context(), req.Token, req.NewPassword); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"message": "Password reset successfully",
	})
}

// ListUsers returns paginated list of users (admin only)
// GET /api/v1/admin/users
func (h *UserHandler) ListUsers(c *fiber.Ctx) error {
	limit := c.QueryInt("limit", 20)
	page := c.QueryInt("page", 1)
	search := c.Query("search", "")

	if limit > 100 {
		limit = 100
	}
	if page < 1 {
		page = 1
	}

	offset := (page - 1) * limit

	users, total, err := h.userService.List(c.Context(), limit, offset, search)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve users",
		})
	}

	// Add roles to response
	type UserWithRoles struct {
		*domain.User
		Roles []string `json:"roles"`
	}

	usersWithRoles := make([]UserWithRoles, len(users))
	for i, user := range users {
		roles, _ := h.userService.GetUserRolesAllApps(c.Context(), user.ID)
		usersWithRoles[i] = UserWithRoles{
			User:  user,
			Roles: roles,
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"users": usersWithRoles,
		"pagination": fiber.Map{
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + limit - 1) / limit,
		},
	})
}

// GetUser returns a specific user by ID (admin only)
// GET /api/v1/admin/users/:id
func (h *UserHandler) GetUser(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	user, err := h.userService.GetByID(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	// Get user roles (for all apps)
	type UserWithRoles struct {
		*domain.User
		Roles []string `json:"roles"`
	}

	roles, _ := h.userService.GetUserRolesAllApps(c.Context(), user.ID)
	response := UserWithRoles{
		User:  user,
		Roles: roles,
	}

	return c.Status(fiber.StatusOK).JSON(response)
}
