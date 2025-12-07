package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/andressep95/auth-service/internal/repository"
)

type SessionHandler struct {
	sessionRepo repository.SessionRepository
}

func NewSessionHandler(sessionRepo repository.SessionRepository) *SessionHandler {
	return &SessionHandler{
		sessionRepo: sessionRepo,
	}
}

// SessionResponse represents a session without sensitive data
type SessionResponse struct {
	ID        string  `json:"id"`
	UserAgent *string `json:"user_agent,omitempty"`
	IPAddress *string `json:"ip_address,omitempty"`
	ExpiresAt string  `json:"expires_at"`
	CreatedAt string  `json:"created_at"`
	IsCurrent bool    `json:"is_current"`
}

// GetMySessions lists all active sessions for the current user
// GET /api/v1/users/me/sessions
func (h *SessionHandler) GetMySessions(c *fiber.Ctx) error {
	// Get user ID from context (set by auth middleware)
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Get current session ID from context if available (optional)
	currentSessionID := c.Locals("session_id")
	var currentSessionUUID *uuid.UUID
	if sessionID, ok := currentSessionID.(uuid.UUID); ok {
		currentSessionUUID = &sessionID
	}

	// Retrieve all active sessions for the user
	sessions, err := h.sessionRepo.GetByUserID(c.Context(), userID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to retrieve sessions",
		})
	}

	// Convert to response format (hide sensitive data)
	response := make([]SessionResponse, len(sessions))
	for i, session := range sessions {
		isCurrent := false
		if currentSessionUUID != nil && session.ID == *currentSessionUUID {
			isCurrent = true
		}

		response[i] = SessionResponse{
			ID:        session.ID.String(),
			UserAgent: session.UserAgent,
			IPAddress: session.IPAddress,
			ExpiresAt: session.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			CreatedAt: session.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			IsCurrent: isCurrent,
		}
	}

	return c.JSON(fiber.Map{
		"sessions": response,
		"count":    len(response),
	})
}

// DeleteSession closes a specific session by ID
// DELETE /api/v1/users/me/sessions/:id
func (h *SessionHandler) DeleteSession(c *fiber.Ctx) error {
	// Get user ID from context
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Parse session ID from URL parameter
	sessionID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid session ID",
		})
	}

	// Verify session belongs to the user (security check)
	session, err := h.sessionRepo.GetByID(c.Context(), sessionID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Session not found",
		})
	}

	// Ensure user owns this session
	if session.UserID != userID {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "You can only delete your own sessions",
		})
	}

	// Delete the session
	if err := h.sessionRepo.Delete(c.Context(), sessionID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete session",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Session closed successfully",
	})
}

// DeleteAllSessions closes all sessions for the current user
// DELETE /api/v1/users/me/sessions
func (h *SessionHandler) DeleteAllSessions(c *fiber.Ctx) error {
	// Get user ID from context
	userID, ok := c.Locals("user_id").(uuid.UUID)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Check if user wants to exclude current session
	excludeCurrent := c.QueryBool("exclude_current", false)

	if excludeCurrent {
		// Get current session ID
		currentSessionID, ok := c.Locals("session_id").(uuid.UUID)
		if !ok {
			// If we can't identify current session, delete all
			if err := h.sessionRepo.DeleteByUserID(c.Context(), userID); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": "Failed to delete sessions",
				})
			}
			return c.JSON(fiber.Map{
				"message": "All sessions closed successfully",
			})
		}

		// Get all sessions and delete all except current
		sessions, err := h.sessionRepo.GetByUserID(c.Context(), userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to retrieve sessions",
			})
		}

		deletedCount := 0
		for _, session := range sessions {
			if session.ID != currentSessionID {
				if err := h.sessionRepo.Delete(c.Context(), session.ID); err != nil {
					// Log error but continue
					continue
				}
				deletedCount++
			}
		}

		return c.JSON(fiber.Map{
			"message": "Other sessions closed successfully",
			"deleted": deletedCount,
		})
	}

	// Delete all sessions (including current)
	if err := h.sessionRepo.DeleteByUserID(c.Context(), userID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete sessions",
		})
	}

	return c.JSON(fiber.Map{
		"message": "All sessions closed successfully",
	})
}
