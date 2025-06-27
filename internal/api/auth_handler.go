package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"yumsg-server/internal/auth"
	"yumsg-server/internal/models"
	"yumsg-server/internal/services"
)

// AuthHandler handles authentication-related HTTP requests
type AuthHandler struct {
	userService *services.UserService
	authService *auth.AuthService
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(userService *services.UserService, authService *auth.AuthService) *AuthHandler {
	return &AuthHandler{
		userService: userService,
		authService: authService,
	}
}

// Register handles user registration
// POST /api/auth/register
func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "validation_failed",
			ErrorCode:        "INVALID_REQUEST_DATA",
			ErrorDescription: "Invalid request data format",
			ValidationErrors: extractValidationErrors(err),
		})
		return
	}

	// Create user
	user, err := h.userService.CreateUser(&req)
	if err != nil {
		errorCode, statusCode := h.mapUserServiceError(err)

		c.JSON(statusCode, models.ErrorResponse{
			Success:          false,
			Error:            "registration_failed",
			ErrorCode:        errorCode,
			ErrorDescription: err.Error(),
		})
		return
	}

	// Return success response
	response := models.AuthResponse{
		Success: true,
		Message: "Пользователь успешно зарегистрирован",
		User: models.UserInfo{
			ID:          user.ID.String(),
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Status:      string(user.Status),
			CreatedAt:   user.CreatedAt.Format(time.RFC3339),
		},
	}

	c.JSON(http.StatusCreated, response)
}

// Login handles user authentication
// POST /api/auth/login
func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "validation_failed",
			ErrorCode:        "INVALID_REQUEST_DATA",
			ErrorDescription: "Invalid request data format",
			ValidationErrors: extractValidationErrors(err),
		})
		return
	}

	// Authenticate user
	user, token, expiresAt, err := h.userService.AuthenticateUser(&req)
	if err != nil {
		errorCode, statusCode := h.mapAuthError(err)

		c.JSON(statusCode, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_failed",
			ErrorCode:        errorCode,
			ErrorDescription: err.Error(),
		})
		return
	}

	// Prepare last seen
	var lastSeenStr *string
	if user.LastSeen != nil {
		lastSeenFormatted := user.LastSeen.Format(time.RFC3339)
		lastSeenStr = &lastSeenFormatted
	}

	// Return success response
	response := models.AuthResponse{
		Success:        true,
		Message:        "Авторизация успешна",
		Token:          token,
		TokenExpiresAt: expiresAt.Format(time.RFC3339),
		User: models.UserInfo{
			ID:          user.ID.String(),
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Status:      string(user.Status),
			LastSeen:    lastSeenStr,
			CreatedAt:   user.CreatedAt.Format(time.RFC3339),
		},
		Organization: &models.OrganizationBrief{
			ID:     user.Organization.ID.String(),
			Name:   user.Organization.Name,
			Domain: user.Organization.Domain,
		},
	}

	c.JSON(http.StatusOK, response)
}

// RefreshToken handles token refresh (placeholder for future implementation)
// POST /api/auth/refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// This would be implemented if refresh tokens are needed
	c.JSON(http.StatusNotImplemented, models.ErrorResponse{
		Success:          false,
		Error:            "not_implemented",
		ErrorCode:        "REFRESH_NOT_IMPLEMENTED",
		ErrorDescription: "Token refresh is not implemented yet",
	})
}

// Logout handles user logout (placeholder - stateless JWT doesn't require server-side logout)
// POST /api/auth/logout
func (h *AuthHandler) Logout(c *gin.Context) {
	// In a stateless JWT system, logout is handled client-side by removing the token
	// However, we can log the action for audit purposes

	_, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	// Log logout action (could be implemented in audit service)
	// auditService.LogAction(userID, "logout", c.ClientIP())

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Успешный выход из системы",
	})
}

// ValidateToken validates the current JWT token
// GET /api/auth/validate
func (h *AuthHandler) ValidateToken(c *gin.Context) {
	// If we reach this point, the token is valid (middleware checked it)
	userID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_failed",
			ErrorCode:        "INVALID_TOKEN_DATA",
			ErrorDescription: "Invalid token data",
		})
		return
	}

	// Get user details
	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Success:          false,
				Error:            "user_not_found",
				ErrorCode:        "USER_NOT_FOUND",
				ErrorDescription: "User associated with token not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve user information",
		})
		return
	}

	// Check if user is blocked
	if user.IsBlocked {
		c.JSON(http.StatusForbidden, models.ErrorResponse{
			Success:          false,
			Error:            "user_blocked",
			ErrorCode:        "USER_BLOCKED",
			ErrorDescription: "User account is blocked",
		})
		return
	}

	// Prepare last seen
	var lastSeenStr *string
	if user.LastSeen != nil {
		lastSeenFormatted := user.LastSeen.Format(time.RFC3339)
		lastSeenStr = &lastSeenFormatted
	}

	// Return user information
	response := models.AuthResponse{
		Success: true,
		Message: "Token is valid",
		User: models.UserInfo{
			ID:          user.ID.String(),
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Status:      string(user.Status),
			LastSeen:    lastSeenStr,
			CreatedAt:   user.CreatedAt.Format(time.RFC3339),
		},
		Organization: &models.OrganizationBrief{
			ID:     user.Organization.ID.String(),
			Name:   user.Organization.Name,
			Domain: user.Organization.Domain,
		},
	}

	c.JSON(http.StatusOK, response)
}

// Helper methods

// mapUserServiceError maps user service errors to API error codes
func (h *AuthHandler) mapUserServiceError(err error) (string, int) {
	switch {
	case errors.Is(err, services.ErrUserAlreadyExists):
		return "USERNAME_EXISTS", http.StatusConflict
	case errors.Is(err, services.ErrOrganizationNotFound):
		return "INVALID_DOMAIN", http.StatusBadRequest
	case errors.Is(err, services.ErrInvalidUserData):
		return "WEAK_PASSWORD", http.StatusBadRequest
	case errors.Is(err, gorm.ErrDuplicatedKey):
		return "USERNAME_EXISTS", http.StatusConflict
	default:
		return "SERVER_ERROR", http.StatusInternalServerError
	}
}

// mapAuthError maps authentication errors to API error codes
func (h *AuthHandler) mapAuthError(err error) (string, int) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "INVALID_CREDENTIALS", http.StatusUnauthorized
	case errors.Is(err, auth.ErrUserBlocked):
		return "USER_BLOCKED", http.StatusForbidden
	case errors.Is(err, services.ErrUserNotFound):
		return "USER_NOT_FOUND", http.StatusUnauthorized
	default:
		return "SERVER_ERROR", http.StatusInternalServerError
	}
}

// extractValidationErrors extracts validation errors from binding error
func extractValidationErrors(err error) map[string][]string {
	validationErrors := make(map[string][]string)

	// This is a simplified implementation
	// In a real application, you would parse the specific validation errors
	// from the gin binding error and map them to field names

	validationErrors["general"] = []string{err.Error()}

	return validationErrors
}

// HealthCheck provides a simple health check endpoint
// GET /api/ping
func (h *AuthHandler) HealthCheck(c *gin.Context) {
	response := models.PingResponse{
		Success:    true,
		Message:    "YuMSG Server is running",
		Version:    "1.0.0", // This could be injected from build info
		Timestamp:  time.Now().Unix(),
		ServerTime: time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}
