package handler

import (
	"net/http"

	"github.com/andressep95/auth-service/internal/service"
	"github.com/andressep95/auth-service/pkg/validator"
	"github.com/gofiber/fiber/v2"
)

type AppHandler struct {
	appService *service.AppService
	validator  *validator.Validator
}

func NewAppHandler(appService *service.AppService, validator *validator.Validator) *AppHandler {
	return &AppHandler{
		appService: appService,
		validator:  validator,
	}
}

type CreateAppRequest struct {
	Name        string `json:"name" validate:"required,min=2,max=100"`
	Description string `json:"description" validate:"max=500"`
}

// CreateApp creates a new application (super admin only)
func (h *AppHandler) CreateApp(c *fiber.Ctx) error {
	var req CreateAppRequest
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

	app, err := h.appService.CreateApp(c.Context(), req.Name, req.Description)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to create app",
			"details": err.Error(),
		})
	}

	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"message": "App created successfully",
		"app": fiber.Map{
			"id":          app.ID,
			"name":        app.Name,
			"client_id":   app.ClientID,
			"description": app.Description,
			"created_at":  app.CreatedAt,
		},
	})
}

// ListApps lists all applications (super admin only)
func (h *AppHandler) ListApps(c *fiber.Ctx) error {
	apps, err := h.appService.ListApps(c.Context())
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to list apps",
		})
	}

	return c.JSON(fiber.Map{
		"apps":  apps,
		"count": len(apps),
	})
}

// GetApp gets a specific application (super admin only)
func (h *AppHandler) GetApp(c *fiber.Ctx) error {
	appID := c.Params("id")
	if appID == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   true,
			"message": "App ID is required",
		})
	}

	app, err := h.appService.GetAppByID(c.Context(), appID)
	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error":   true,
			"message": "App not found",
		})
	}

	return c.JSON(app)
}
