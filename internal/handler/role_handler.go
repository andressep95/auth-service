package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
)

type RoleHandler struct {
	roleService *service.RoleService
	validator   *validator.Validator
}

func NewRoleHandler(roleService *service.RoleService, validator *validator.Validator) *RoleHandler {
	return &RoleHandler{
		roleService: roleService,
		validator:   validator,
	}
}

// CreateRole creates a new role (admin only)
// POST /api/v1/admin/roles
func (h *RoleHandler) CreateRole(c *fiber.Ctx) error {
	var req struct {
		AppID       string `json:"app_id" validate:"required,uuid"`
		Name        string `json:"name" validate:"required,min=2,max=50"`
		Description string `json:"description" validate:"max=255"`
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

	appID, _ := uuid.Parse(req.AppID)

	role, err := h.roleService.CreateRole(c.Context(), appID, req.Name, req.Description)
	if err != nil {
		if err == service.ErrRoleAlreadyExists {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Role already exists",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.Status(fiber.StatusCreated).JSON(role)
}

// GetRoles lists all roles for an app (admin/moderator)
// GET /api/v1/admin/roles?app_id=uuid
func (h *RoleHandler) GetRoles(c *fiber.Ctx) error {
	appIDStr := c.Query("app_id")
	if appIDStr == "" {
		// Default to base app
		appIDStr = "00000000-0000-0000-0000-000000000000"
	}

	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid app_id",
		})
	}

	roles, err := h.roleService.GetRolesByApp(c.Context(), appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"roles": roles,
		"count": len(roles),
	})
}

// GetRole retrieves a specific role (admin/moderator)
// GET /api/v1/admin/roles/:id
func (h *RoleHandler) GetRole(c *fiber.Ctx) error {
	roleID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role ID",
		})
	}

	role, err := h.roleService.GetRole(c.Context(), roleID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Role not found",
		})
	}

	return c.JSON(role)
}

// UpdateRole updates a role (admin only)
// PUT /api/v1/admin/roles/:id
func (h *RoleHandler) UpdateRole(c *fiber.Ctx) error {
	roleID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role ID",
		})
	}

	var req struct {
		Name        string `json:"name" validate:"required,min=2,max=50"`
		Description string `json:"description" validate:"max=255"`
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

	err = h.roleService.UpdateRole(c.Context(), roleID, req.Name, req.Description)
	if err != nil {
		if err == service.ErrRoleNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Role not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Role updated successfully",
	})
}

// DeleteRole deletes a role (admin only)
// DELETE /api/v1/admin/roles/:id
func (h *RoleHandler) DeleteRole(c *fiber.Ctx) error {
	roleID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role ID",
		})
	}

	err = h.roleService.DeleteRole(c.Context(), roleID)
	if err != nil {
		if err == service.ErrRoleNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Role not found",
			})
		}
		if err == service.ErrCannotDeleteRole {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "Cannot delete role with assigned users",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Role deleted successfully",
	})
}

// AssignRoleToUser assigns a role to a user (admin only)
// POST /api/v1/admin/users/:userId/roles/:roleId
func (h *RoleHandler) AssignRoleToUser(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	roleID, err := uuid.Parse(c.Params("roleId"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role ID",
		})
	}

	err = h.roleService.AssignRoleToUser(c.Context(), userID, roleID)
	if err != nil {
		if err == service.ErrRoleNotFound {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": "Role not found",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Role assigned successfully",
	})
}

// RemoveRoleFromUser removes a role from a user (admin only)
// DELETE /api/v1/admin/users/:userId/roles/:roleId
func (h *RoleHandler) RemoveRoleFromUser(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	roleID, err := uuid.Parse(c.Params("roleId"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role ID",
		})
	}

	err = h.roleService.RemoveRoleFromUser(c.Context(), userID, roleID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Role assignment not found",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Role removed successfully",
	})
}

// GetUserRoles lists roles for a specific user (admin/moderator or self)
// GET /api/v1/admin/users/:userId/roles
func (h *RoleHandler) GetUserRoles(c *fiber.Ctx) error {
	userID, err := uuid.Parse(c.Params("userId"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid user ID",
		})
	}

	// Default to base app
	appID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	roles, err := h.roleService.GetUserRoles(c.Context(), userID, appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"roles": roles,
		"count": len(roles),
	})
}

// GetMyRoles lists roles for the current authenticated user
// GET /api/v1/users/me/roles
func (h *RoleHandler) GetMyRoles(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Default to base app
	appID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	roles, err := h.roleService.GetUserRoles(c.Context(), userID, appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"roles": roles,
		"count": len(roles),
	})
}

// GetRolePermissions lists permissions for a role (admin/moderator)
// GET /api/v1/admin/roles/:id/permissions
func (h *RoleHandler) GetRolePermissions(c *fiber.Ctx) error {
	roleID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid role ID",
		})
	}

	permissions, err := h.roleService.GetRolePermissions(c.Context(), roleID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"permissions": permissions,
		"count":       len(permissions),
	})
}

// GetMyPermissions lists permissions for the current authenticated user
// GET /api/v1/users/me/permissions
func (h *RoleHandler) GetMyPermissions(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uuid.UUID)

	// Default to base app
	appID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	permissions, err := h.roleService.GetUserPermissions(c.Context(), userID, appID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"permissions": permissions,
		"count":       len(permissions),
	})
}
