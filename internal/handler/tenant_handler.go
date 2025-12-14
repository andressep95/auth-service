package handler

import (
	"net/http"

	"github.com/andressep95/auth-service/internal/domain"
	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

type TenantHandler struct {
	tenantService *service.TenantService
	validator     *validator.Validator
}

func NewTenantHandler(tenantService *service.TenantService, validator *validator.Validator) *TenantHandler {
	return &TenantHandler{
		tenantService: tenantService,
		validator:     validator,
	}
}

// CreateTenantRequest represents the request body for creating a tenant
type CreateTenantRequest struct {
	AppID    string  `json:"app_id" validate:"required,uuid"`
	Name     string  `json:"name" validate:"required,min=2,max=255"`
	Slug     string  `json:"slug" validate:"omitempty,min=3,max=100"` // Optional, auto-generated if empty
	Type     string  `json:"type" validate:"omitempty,oneof=public workspace enterprise"`
	MaxUsers *int    `json:"max_users" validate:"omitempty,min=1"`
	OwnerID  *string `json:"owner_id" validate:"omitempty,uuid"`
}

// UpdateTenantRequest represents the request body for updating a tenant
type UpdateTenantRequest struct {
	Name     *string `json:"name" validate:"omitempty,min=2,max=255"`
	Slug     *string `json:"slug" validate:"omitempty,min=3,max=100"`
	MaxUsers *int    `json:"max_users" validate:"omitempty,min=1"`
	Status   *string `json:"status" validate:"omitempty,oneof=active suspended trial"`
}

// CreateInvitationRequest represents the request body for creating an invitation
type CreateInvitationRequest struct {
	RoleID         *string `json:"role_id" validate:"omitempty,uuid"`
	MaxUses        *int    `json:"max_uses" validate:"omitempty,min=1"`
	ExpiresInHours int     `json:"expires_in_hours" validate:"required,min=1,max=720"` // Max 30 days
}

// CreateTenant creates a new tenant (admin only)
// POST /api/v1/admin/tenants
func (h *TenantHandler) CreateTenant(c *fiber.Ctx) error {
	var req CreateTenantRequest
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

	// Parse app_id
	appID, err := uuid.Parse(req.AppID)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid app_id",
		})
	}

	// Parse owner_id if provided
	var ownerID *uuid.UUID
	if req.OwnerID != nil {
		parsed, err := uuid.Parse(*req.OwnerID)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid owner_id",
			})
		}
		ownerID = &parsed
	}

	// Parse tenant type
	tenantType := domain.TenantTypeWorkspace // Default
	if req.Type != "" {
		tenantType = domain.TenantType(req.Type)
	}

	tenant, err := h.tenantService.CreateTenant(c.Context(), appID, req.Name, req.Slug, tenantType, ownerID, req.MaxUsers)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to create tenant",
			"details": err.Error(),
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "Tenant created successfully",
		"tenant":  tenant,
	})
}

// ListTenants lists all tenants for an app with pagination (admin only)
// GET /api/v1/admin/tenants?app_id=xxx&page=1&limit=20
func (h *TenantHandler) ListTenants(c *fiber.Ctx) error {
	appIDStr := c.Query("app_id")
	if appIDStr == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "app_id query parameter is required",
		})
	}

	appID, err := uuid.Parse(appIDStr)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid app_id",
		})
	}

	limit := c.QueryInt("limit", 20)
	page := c.QueryInt("page", 1)

	if limit > 100 {
		limit = 100
	}
	if page < 1 {
		page = 1
	}

	offset := (page - 1) * limit

	tenants, total, err := h.tenantService.ListTenants(c.Context(), appID, limit, offset)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to list tenants",
		})
	}

	return c.JSON(fiber.Map{
		"tenants": tenants,
		"pagination": fiber.Map{
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + limit - 1) / limit,
		},
	})
}

// GetTenant gets a specific tenant by ID (admin only)
// GET /api/v1/admin/tenants/:id
func (h *TenantHandler) GetTenant(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid tenant ID",
		})
	}

	tenant, err := h.tenantService.GetTenantByID(c.Context(), tenantID)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error":   true,
			"message": "Tenant not found",
		})
	}

	return c.JSON(tenant)
}

// UpdateTenant updates a tenant (admin only)
// PUT /api/v1/admin/tenants/:id
func (h *TenantHandler) UpdateTenant(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid tenant ID",
		})
	}

	var req UpdateTenantRequest
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

	// Convert status string to domain type if provided
	var status *domain.TenantStatus
	if req.Status != nil {
		s := domain.TenantStatus(*req.Status)
		status = &s
	}

	tenant, err := h.tenantService.UpdateTenant(c.Context(), tenantID, req.Name, req.Slug, req.MaxUsers, status)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to update tenant",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Tenant updated successfully",
		"tenant":  tenant,
	})
}

// CreateInvitation creates an invitation for a tenant (admin/owner only)
// POST /api/v1/admin/tenants/:id/invitations
func (h *TenantHandler) CreateInvitation(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid tenant ID",
		})
	}

	var req CreateInvitationRequest
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

	// Get user ID from context (set by auth middleware)
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
			"error":   true,
			"message": "Unauthorized",
		})
	}

	// Parse role_id if provided
	var roleID *uuid.UUID
	if req.RoleID != nil {
		parsed, err := uuid.Parse(*req.RoleID)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid role_id",
			})
		}
		roleID = &parsed
	}

	invitation, token, err := h.tenantService.CreateInvitation(
		c.Context(),
		tenantID,
		userID,
		roleID,
		req.MaxUses,
		req.ExpiresInHours,
	)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to create invitation",
			"details": err.Error(),
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "Invitation created successfully",
		"invitation": fiber.Map{
			"id":           invitation.ID,
			"tenant_id":    invitation.TenantID,
			"max_uses":     invitation.MaxUses,
			"current_uses": invitation.CurrentUses,
			"expires_at":   invitation.ExpiresAt,
			"created_at":   invitation.CreatedAt,
		},
		"token": token, // Only exposed once at creation
	})
}

// ListInvitations lists invitations for a tenant (admin/owner only)
// GET /api/v1/admin/tenants/:id/invitations
func (h *TenantHandler) ListInvitations(c *fiber.Ctx) error {
	tenantID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid tenant ID",
		})
	}

	limit := c.QueryInt("limit", 20)
	page := c.QueryInt("page", 1)

	if limit > 100 {
		limit = 100
	}
	if page < 1 {
		page = 1
	}

	offset := (page - 1) * limit

	invitations, total, err := h.tenantService.ListInvitations(c.Context(), tenantID, limit, offset)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to list invitations",
		})
	}

	return c.JSON(fiber.Map{
		"invitations": invitations,
		"pagination": fiber.Map{
			"total":       total,
			"page":        page,
			"limit":       limit,
			"total_pages": (total + limit - 1) / limit,
		},
	})
}

// RevokeInvitation revokes an invitation (admin/owner only)
// DELETE /api/v1/admin/tenants/:id/invitations/:invitationId
func (h *TenantHandler) RevokeInvitation(c *fiber.Ctx) error {
	invitationID, err := uuid.Parse(c.Params("invitationId"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid invitation ID",
		})
	}

	if err := h.tenantService.RevokeInvitation(c.Context(), invitationID); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to revoke invitation",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"message": "Invitation revoked successfully",
	})
}

// ValidateInvitation validates an invitation token (public endpoint)
// GET /api/v1/auth/validate-invitation/:token
func (h *TenantHandler) ValidateInvitation(c *fiber.Ctx) error {
	token := c.Params("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "Token is required",
		})
	}

	invitation, tenant, err := h.tenantService.ValidateInvitationToken(c.Context(), token)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"valid": true,
		"tenant": fiber.Map{
			"id":   tenant.ID,
			"name": tenant.Name,
			"slug": tenant.Slug,
			"type": tenant.Type,
		},
		"invitation": fiber.Map{
			"id":         invitation.ID,
			"expires_at": invitation.ExpiresAt,
		},
	})
}
