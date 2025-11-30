package handler

import (
	"net/http"

	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
	"github.com/gofiber/fiber/v2"
)

type SetupHandler struct {
	userService *service.UserService
	roleService *service.RoleService
	validator   *validator.Validator
}

func NewSetupHandler(userService *service.UserService, roleService *service.RoleService, validator *validator.Validator) *SetupHandler {
	return &SetupHandler{
		userService: userService,
		roleService: roleService,
		validator:   validator,
	}
}

type CreateSuperAdminRequest struct {
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=8"`
	FirstName string `json:"first_name" validate:"required,min=2"`
	LastName  string `json:"last_name" validate:"required,min=2"`
}

// CreateSuperAdmin creates the first super admin user
// This endpoint only works if no super admin exists yet
func (h *SetupHandler) CreateSuperAdmin(c *fiber.Ctx) error {
	var req CreateSuperAdminRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	if err := h.validator.Validate(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	// Check if super admin already exists
	exists, err := h.userService.SuperAdminExists(c.Context())
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to check super admin existence",
		})
	}

	if exists {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error":   true,
			"message": "Super admin already exists. This endpoint can only be used once.",
		})
	}

	// Create super admin
	user, err := h.userService.CreateSuperAdmin(c.Context(), req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to create super admin",
			"details": err.Error(),
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "Super admin created successfully",
		"user": fiber.Map{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
			"role":       "super_admin",
		},
	})
}
