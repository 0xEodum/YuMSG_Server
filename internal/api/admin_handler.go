package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"yumsg-server/internal/auth"
	"yumsg-server/internal/models"
	"yumsg-server/internal/services"
)

// AdminHandler handles administrative HTTP requests
type AdminHandler struct {
	adminService *services.AdminService
	userService  *services.UserService
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(adminService *services.AdminService, userService *services.UserService) *AdminHandler {
	return &AdminHandler{
		adminService: adminService,
		userService:  userService,
	}
}

// AdminMiddleware checks if the user has admin privileges
func (h *AdminHandler) AdminMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		userID, err := auth.GetUserIDFromContext(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, models.ErrorResponse{
				Success:          false,
				Error:            "authentication_required",
				ErrorCode:        "MISSING_USER_ID",
				ErrorDescription: "User ID not found in token",
			})
			c.Abort()
			return
		}

		// Check if user is admin
		isAdmin, err := h.adminService.IsUserAdmin(userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.ErrorResponse{
				Success:          false,
				Error:            "server_error",
				ErrorCode:        "ADMIN_CHECK_FAILED",
				ErrorDescription: "Failed to verify admin privileges",
			})
			c.Abort()
			return
		}

		if !isAdmin {
			c.JSON(http.StatusForbidden, models.ErrorResponse{
				Success:          false,
				Error:            "access_denied",
				ErrorCode:        "INSUFFICIENT_PRIVILEGES",
				ErrorDescription: "Admin privileges required",
			})
			c.Abort()
			return
		}

		c.Next()
	})
}

// GetAllUsers returns all users with admin information
// GET /api/admin/users
func (h *AdminHandler) GetAllUsers(c *gin.Context) {
	// Parse query parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	statusFilter := c.DefaultQuery("status", "all")
	sortBy := c.DefaultQuery("sort", "created_at")

	// Validate parameters
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	// Valid status filters
	validStatuses := map[string]bool{
		"all":                  true,
		"online":               true,
		"offline_connected":    true,
		"offline_disconnected": true,
		"blocked":              true,
	}
	if !validStatuses[statusFilter] {
		statusFilter = "all"
	}

	// Valid sort options
	validSorts := map[string]bool{
		"created_at":   true,
		"last_seen":    true,
		"email":        true,
		"status":       true,
		"display_name": true,
	}
	if !validSorts[sortBy] {
		sortBy = "created_at"
	}

	// Get users
	users, total, err := h.adminService.GetAllUsersForAdmin(limit, offset, statusFilter, sortBy)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve users",
		})
		return
	}

	response := models.AdminUsersResponse{
		Success:    true,
		TotalUsers: total,
		Limit:      limit,
		Offset:     offset,
		Users:      users,
	}

	c.JSON(http.StatusOK, response)
}

// BlockUser blocks a specific user
// POST /api/admin/users/{id}/block
func (h *AdminHandler) BlockUser(c *gin.Context) {
	// Get admin user ID
	adminID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "Admin user ID not found in token",
		})
		return
	}

	// Parse target user ID
	userIDParam := c.Param("id")
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_user_id",
			ErrorCode:        "INVALID_USER_ID",
			ErrorDescription: "Invalid user ID format",
		})
		return
	}

	// Parse request body
	var req models.BlockUserRequest
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

	// Validate that admin is not trying to block themselves
	if userID == adminID {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_operation",
			ErrorCode:        "CANNOT_BLOCK_SELF",
			ErrorDescription: "Administrators cannot block themselves",
		})
		return
	}

	// Check if user exists
	_, err = h.userService.GetUserByID(userID)
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
			ErrorDescription: "Failed to verify user existence",
		})
		return
	}

	// Block user
	blockedUserInfo, err := h.adminService.BlockUserByAdmin(userID, adminID, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "block_failed",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to block user",
		})
		return
	}

	response := models.BlockUserResponse{
		Success:     true,
		Message:     "Пользователь заблокирован",
		BlockedUser: *blockedUserInfo,
	}

	c.JSON(http.StatusOK, response)
}

// UnblockUser unblocks a specific user
// POST /api/admin/users/{id}/unblock
func (h *AdminHandler) UnblockUser(c *gin.Context) {
	// Get admin user ID
	adminID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "Admin user ID not found in token",
		})
		return
	}

	// Parse target user ID
	userIDParam := c.Param("id")
	userID, err := uuid.Parse(userIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_user_id",
			ErrorCode:        "INVALID_USER_ID",
			ErrorDescription: "Invalid user ID format",
		})
		return
	}

	// Unblock user
	if err := h.adminService.UnblockUser(userID, adminID); err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "unblock_failed",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to unblock user",
		})
		return
	}

	response := models.APIResponse{
		Success: true,
		Message: "Пользователь разблокирован",
		Data: map[string]interface{}{
			"user_id":      userID.String(),
			"unblocked_at": time.Now().Format(time.RFC3339),
			"unblocked_by": adminID.String(),
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetServerStats returns server statistics
// GET /api/admin/stats
func (h *AdminHandler) GetServerStats(c *gin.Context) {
	// Parse period parameter
	periodParam := c.DefaultQuery("period", "24h")

	var period time.Duration
	var err error

	switch periodParam {
	case "1h":
		period = time.Hour
	case "24h":
		period = 24 * time.Hour
	case "7d":
		period = 7 * 24 * time.Hour
	case "30d":
		period = 30 * 24 * time.Hour
	default:
		period = 24 * time.Hour
		periodParam = "24h"
	}

	// Get server statistics
	stats, err := h.adminService.GetServerStats(period)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "STATS_GENERATION_FAILED",
			ErrorDescription: "Failed to generate server statistics",
		})
		return
	}

	response := models.StatsResponse{
		Success:     true,
		Period:      periodParam,
		Stats:       *stats,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

// GetBlockedUsers returns all blocked users
// GET /api/admin/blocked-users
func (h *AdminHandler) GetBlockedUsers(c *gin.Context) {
	blockedUsers, err := h.adminService.GetBlockedUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve blocked users",
		})
		return
	}

	response := map[string]interface{}{
		"success":       true,
		"blocked_users": blockedUsers,
		"total":         len(blockedUsers),
	}

	c.JSON(http.StatusOK, response)
}

// CleanupExpiredBlocks removes expired user blocks
// POST /api/admin/cleanup/expired-blocks
func (h *AdminHandler) CleanupExpiredBlocks(c *gin.Context) {
	unblockedCount, err := h.adminService.CleanupExpiredBlocks()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "cleanup_failed",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to cleanup expired blocks",
		})
		return
	}

	response := models.APIResponse{
		Success: true,
		Message: "Expired blocks cleaned up successfully",
		Data: map[string]interface{}{
			"unblocked_count": unblockedCount,
			"cleaned_at":      time.Now().Format(time.RFC3339),
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetSystemHealth returns system health information
// GET /api/admin/health
func (h *AdminHandler) GetSystemHealth(c *gin.Context) {
	// Basic health check
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"services": map[string]interface{}{
			"database":  "connected",
			"websocket": "active",
		},
		"version": "1.0.0",
	}

	c.JSON(http.StatusOK, health)
}

// GetAuditLogs returns audit logs (if implemented)
// GET /api/admin/audit-logs
func (h *AdminHandler) GetAuditLogs(c *gin.Context) {
	// Placeholder for audit logs functionality
	c.JSON(http.StatusNotImplemented, models.ErrorResponse{
		Success:          false,
		Error:            "not_implemented",
		ErrorCode:        "AUDIT_LOGS_NOT_IMPLEMENTED",
		ErrorDescription: "Audit logs functionality is not implemented yet",
	})
}
