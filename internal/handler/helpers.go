package handler

import (
	"log"
	"net/url"

	"github.com/gofiber/fiber/v2"
)

// getOriginFromRequest extracts the origin from multiple sources (fallback chain)
// Priority: Origin header > Referer header > Host header
func getOriginFromRequest(c *fiber.Ctx) string {
	// Try Origin header first (sent in CORS requests)
	origin := c.Get("Origin")
	if origin != "" {
		log.Printf("[HELPER] Origin from Origin header: %s", origin)
		return origin
	}

	// Try Referer header (sent when navigating from another page)
	referer := c.Get("Referer")
	if referer != "" {
		if parsedURL, err := url.Parse(referer); err == nil {
			origin = parsedURL.Scheme + "://" + parsedURL.Host
			log.Printf("[HELPER] Origin from Referer header: %s", origin)
			return origin
		}
	}

	// Fallback to Host header (always present, construct origin)
	host := c.Get("Host")
	if host != "" {
		// Determine scheme from protocol
		scheme := "http"
		if c.Protocol() == "https" || c.Get("X-Forwarded-Proto") == "https" {
			scheme = "https"
		}
		origin = scheme + "://" + host
		log.Printf("[HELPER] Origin from Host header: %s", origin)
		return origin
	}

	return ""
}
