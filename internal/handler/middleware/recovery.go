package middleware

import (
	"fmt"
	"log"
	"runtime/debug"

	"github.com/gofiber/fiber/v2"
)

// RecoveryMiddleware recovers from panics and returns 500 error
func RecoveryMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		defer func() {
			if r := recover(); r != nil {
				// Get stack trace
				stack := debug.Stack()

				// Log panic with stack trace
				log.Printf("PANIC: %v\n%s", r, stack)

				// Return 500 Internal Server Error
				err := c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": fmt.Sprintf("internal server error: %v", r),
				})
				if err != nil {
					log.Printf("Error sending panic response: %v", err)
				}
			}
		}()

		// Continue to next handler
		return c.Next()
	}
}
