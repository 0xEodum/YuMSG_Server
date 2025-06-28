package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"yumsg-server/internal/auth"
	"yumsg-server/internal/interfaces"
	"yumsg-server/internal/models"
	"yumsg-server/internal/services"
)

// UserHandler handles user-related HTTP requests
type UserHandler struct {
	userService    *services.UserService
	messageService *services.MessageService
	wsManager      interfaces.WebSocketManagerInterface
}

// NewUserHandler creates a new user handler
func NewUserHandler(userService *services.UserService, messageService *services.MessageService, wsManager interfaces.WebSocketManagerInterface) *UserHandler {
	return &UserHandler{
		userService:    userService,
		messageService: messageService,
		wsManager:      wsManager,
	}
}

// GetProfile returns the current user's profile
// GET /api/users/profile
func (h *UserHandler) GetProfile(c *gin.Context) {
	userID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	user, err := h.userService.GetUserByID(userID)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Success:          false,
				Error:            "user_not_found",
				ErrorCode:        "USER_NOT_FOUND",
				ErrorDescription: "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve user profile",
		})
		return
	}

	// Prepare last seen
	var lastSeenStr *string
	if user.LastSeen != nil {
		lastSeenFormatted := user.LastSeen.Format(time.RFC3339)
		lastSeenStr = &lastSeenFormatted
	}

	// Prepare user profile response
	response := models.UserProfileResponse{
		Success: true,
		User: models.DetailedUserProfile{
			ID:          user.ID.String(),
			Username:    user.Username,
			DisplayName: user.DisplayName,
			Email:       user.Email,
			Status:      string(user.Status),
			LastSeen:    lastSeenStr,
			CreatedAt:   user.CreatedAt.Format(time.RFC3339),
			Preferences: models.UserPreferences{
				SelectedAlgorithms: models.AlgorithmSelection{
					Asymmetric: "NTRU",    // Default values
					Symmetric:  "AES-256", // These could be stored in DB
					Signature:  "Falcon",  // if user preferences are implemented
				},
			},
		},
	}

	c.JSON(http.StatusOK, response)
}

// UpdateProfile updates the current user's profile
// PUT /api/users/profile
func (h *UserHandler) UpdateProfile(c *gin.Context) {
	userID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	var req models.UpdateProfileRequest
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

	// Update user profile
	updatedUser, err := h.userService.UpdateUserProfile(userID, &req)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Success:          false,
				Error:            "user_not_found",
				ErrorCode:        "USER_NOT_FOUND",
				ErrorDescription: "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "UPDATE_FAILED",
			ErrorDescription: "Failed to update user profile",
		})
		return
	}

	// Return updated user info
	response := models.APIResponse{
		Success: true,
		Message: "Профиль успешно обновлен",
		Data: map[string]interface{}{
			"id":           updatedUser.ID.String(),
			"username":     updatedUser.Username,
			"display_name": updatedUser.DisplayName,
			"email":        updatedUser.Email,
			"status":       string(updatedUser.Status),
			"updated_at":   updatedUser.UpdatedAt.Format(time.RFC3339),
		},
	}

	c.JSON(http.StatusOK, response)
}

// SearchUsers searches for users in the organization
// GET /api/users/search
func (h *UserHandler) SearchUsers(c *gin.Context) {
	userID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	// Get query parameters
	query := c.Query("q")
	if len(query) < 2 {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "search_failed",
			ErrorCode:        "QUERY_TOO_SHORT",
			ErrorDescription: "Поисковый запрос должен содержать минимум 2 символа",
		})
		return
	}

	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Validate limits
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}

	// Search users
	users, total, err := h.userService.SearchUsers(query, limit, offset, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "search_failed",
			ErrorCode:        "SERVER_ERROR",
			ErrorDescription: "Failed to search users",
		})
		return
	}

	// Convert users to search results
	var searchResults []models.SearchUserResult
	for _, user := range users {
		// Check if current user has active chat with this user
		hasActiveChat, _ := h.userService.HasActiveChat(userID, user.ID)

		// Prepare last seen
		var lastSeenStr *string
		if user.LastSeen != nil {
			lastSeenFormatted := user.LastSeen.Format(time.RFC3339)
			lastSeenStr = &lastSeenFormatted
		}

		searchResults = append(searchResults, models.SearchUserResult{
			ID:            user.ID.String(),
			Username:      user.Username,
			DisplayName:   user.DisplayName,
			Status:        string(user.Status),
			LastSeen:      lastSeenStr,
			HasActiveChat: hasActiveChat,
		})
	}

	response := models.UserSearchResponse{
		Success:    true,
		Query:      query,
		TotalFound: total,
		Limit:      limit,
		Offset:     offset,
		Users:      searchResults,
	}

	c.JSON(http.StatusOK, response)
}

// GetUserStatus returns status information for a specific user
// GET /api/users/{userId}/status
func (h *UserHandler) GetUserStatus(c *gin.Context) {
	userIDParam := c.Param("userId")
	targetUserID, err := uuid.Parse(userIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_user_id",
			ErrorCode:        "INVALID_USER_ID",
			ErrorDescription: "Invalid user ID format",
		})
		return
	}

	// Since 1 server = 1 organization, no need to verify organization membership
	// Get target user and connection info
	targetUser, connection, err := h.userService.GetUserStatus(targetUserID)
	if err != nil {
		if errors.Is(err, services.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Success:          false,
				Error:            "user_not_found",
				ErrorCode:        "USER_NOT_FOUND",
				ErrorDescription: "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to get user status",
		})
		return
	}

	// Prepare connection info
	connectionInfo := models.ConnectionInfo{}
	if connection != nil {
		connectionInfo.ConnectedAt = connection.ConnectedAt.Format(time.RFC3339)
		connectionInfo.LastActivity = connection.LastHeartbeat.Format(time.RFC3339)
	}

	// Prepare last seen
	var lastSeenStr *string
	if targetUser.LastSeen != nil {
		lastSeenFormatted := targetUser.LastSeen.Format(time.RFC3339)
		lastSeenStr = &lastSeenFormatted
	}

	response := models.UserStatusResponse{
		Success: true,
		User: models.UserStatusInfo{
			ID:             targetUser.ID.String(),
			Username:       targetUser.Username,
			DisplayName:    targetUser.DisplayName,
			Status:         string(targetUser.Status),
			LastSeen:       lastSeenStr,
			ConnectionInfo: connectionInfo,
		},
	}

	c.JSON(http.StatusOK, response)
}

// SetOfflineStatus sets user status to offline_connected
// POST /api/presence/offline
func (h *UserHandler) SetOfflineStatus(c *gin.Context) {
	userID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	var req models.SetOfflineRequest
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

	// Update user status through WebSocket manager
	err = h.wsManager.UpdateUserOfflineStatus(userID, req.Reason)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "status_update_failed",
			ErrorCode:        "USER_NOT_ONLINE",
			ErrorDescription: "User must be online to set offline status",
		})
		return
	}

	response := models.PresenceResponse{
		Success:    true,
		Message:    "Статус установлен",
		UserStatus: models.UserStatusInfo{
			// This would be populated with updated user info in a full implementation
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetOnlineUsers returns list of currently online users (helper endpoint)
// GET /api/users/online
func (h *UserHandler) GetOnlineUsers(c *gin.Context) {
	// Get current user ID for filtering
	currentUserID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	// Since 1 server = 1 organization, all users belong to the same organization
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	// Get users with online status
	users, _, err := h.userService.GetAllUsers(limit, offset, "online", "display_name")
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to get online users",
		})
		return
	}

	// Filter out current user and convert to response format
	var onlineUsers []models.SearchUserResult
	for _, user := range users {
		if user.ID != currentUserID {
			// Check active chat
			hasActiveChat, _ := h.userService.HasActiveChat(currentUserID, user.ID)

			// Prepare last seen
			var lastSeenStr *string
			if user.LastSeen != nil {
				lastSeenFormatted := user.LastSeen.Format(time.RFC3339)
				lastSeenStr = &lastSeenFormatted
			}

			onlineUsers = append(onlineUsers, models.SearchUserResult{
				ID:            user.ID.String(),
				Username:      user.Username,
				DisplayName:   user.DisplayName,
				Status:        string(user.Status),
				LastSeen:      lastSeenStr,
				HasActiveChat: hasActiveChat,
			})
		}
	}

	response := models.UserSearchResponse{
		Success:    true,
		Query:      "online_users",
		TotalFound: len(onlineUsers),
		Limit:      limit,
		Offset:     offset,
		Users:      onlineUsers,
	}

	c.JSON(http.StatusOK, response)
}
