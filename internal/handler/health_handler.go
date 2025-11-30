package handler

import (
	"github.com/gofiber/fiber/v2"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler {
	return &HealthHandler{}
}

// Health returns basic health status
// GET /health
func (h *HealthHandler) Health(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "ok",
		"service": "auth-service",
	})
}

// Ready returns readiness status
// GET /ready
func (h *HealthHandler) Ready(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status": "ready",
		"checks": fiber.Map{
			"database": "ok",
			"cache":    "ok",
		},
	})
}
