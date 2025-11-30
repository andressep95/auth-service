package middleware

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
)

// LoggerMiddleware logs HTTP requests and responses
func LoggerMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Record start time
		start := time.Now()

		// Log incoming request
		log.Printf("[%s] %s - Started", c.Method(), c.Path())

		// Process request
		err := c.Next()

		// Calculate request latency
		latency := time.Since(start)

		// Get response status
		status := c.Response().StatusCode()

		// Log request completion
		log.Printf("[%s] %s - Completed in %v with status %d",
			c.Method(),
			c.Path(),
			latency,
			status,
		)

		return err
	}
}
