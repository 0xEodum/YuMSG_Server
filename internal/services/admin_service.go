package services

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"yumsg-server/internal/interfaces"
	"yumsg-server/internal/models"
)

// AdminService handles administrative operations
type AdminService struct {
	db             *gorm.DB
	userService    *UserService
	messageService *MessageService
	wsManager      interfaces.WebSocketManagerInterface
}

// NewAdminService creates a new admin service
func NewAdminService(db *gorm.DB, userService *UserService, messageService *MessageService) *AdminService {
	return &AdminService{
		db:             db,
		userService:    userService,
		messageService: messageService,
		wsManager:      nil, // Will be set later via SetWebSocketManager
	}
}

// SetWebSocketManager sets the WebSocket manager (used to break circular dependency)
func (s *AdminService) SetWebSocketManager(wsManager interfaces.WebSocketManagerInterface) {
	s.wsManager = wsManager
}

// GetServerStats returns comprehensive server statistics
func (s *AdminService) GetServerStats(period time.Duration) (*models.ServerStats, error) {
	stats := &models.ServerStats{}

	// User statistics
	userStats, err := s.getUserStats(period)
	if err != nil {
		return nil, fmt.Errorf("failed to get user stats: %w", err)
	}
	stats.Users = *userStats

	// Message statistics
	messageStats, err := s.messageService.GetMessageStats(period)
	if err != nil {
		return nil, fmt.Errorf("failed to get message stats: %w", err)
	}
	stats.Messages = *messageStats

	// Connection statistics
	connectionStats, err := s.getConnectionStats(period)
	if err != nil {
		return nil, fmt.Errorf("failed to get connection stats: %w", err)
	}
	stats.Connections = *connectionStats

	// System statistics
	systemStats := s.getSystemStats()
	stats.Server = *systemStats

	return stats, nil
}

// getUserStats calculates user statistics
func (s *AdminService) getUserStats(period time.Duration) (*models.UserStats, error) {
	stats := &models.UserStats{}
	since := time.Now().Add(-period)

	// Total users
	var total int64
	if err := s.db.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count total users: %w", err)
	}
	stats.Total = int(total)

	// Online users
	var online int64
	if err := s.db.Model(&models.User{}).Where("status = ?", models.StatusOnline).Count(&online).Error; err != nil {
		return nil, fmt.Errorf("failed to count online users: %w", err)
	}
	stats.Online = int(online)

	// Offline connected users
	var offlineConnected int64
	if err := s.db.Model(&models.User{}).Where("status = ?", models.StatusOfflineConnected).Count(&offlineConnected).Error; err != nil {
		return nil, fmt.Errorf("failed to count offline connected users: %w", err)
	}
	stats.OfflineConnected = int(offlineConnected)

	// Offline disconnected users
	var offlineDisconnected int64
	if err := s.db.Model(&models.User{}).Where("status = ?", models.StatusOfflineDisconnected).Count(&offlineDisconnected).Error; err != nil {
		return nil, fmt.Errorf("failed to count offline disconnected users: %w", err)
	}
	stats.OfflineDisconnected = int(offlineDisconnected)

	// Blocked users
	var blocked int64
	if err := s.db.Model(&models.User{}).Where("is_blocked = true").Count(&blocked).Error; err != nil {
		return nil, fmt.Errorf("failed to count blocked users: %w", err)
	}
	stats.Blocked = int(blocked)

	// New registrations in period
	var newRegistrations int64
	if err := s.db.Model(&models.User{}).Where("created_at >= ?", since).Count(&newRegistrations).Error; err != nil {
		return nil, fmt.Errorf("failed to count new registrations: %w", err)
	}
	stats.NewRegistrations = int(newRegistrations)

	return stats, nil
}

// getConnectionStats calculates connection statistics
func (s *AdminService) getConnectionStats(period time.Duration) (*models.ConnectionStats, error) {
	stats := &models.ConnectionStats{}
	since := time.Now().Add(-period)

	// Active WebSocket connections from manager
	if s.wsManager != nil {
		stats.ActiveWebsockets = s.wsManager.GetActiveConnectionsCount()
	} else {
		stats.ActiveWebsockets = 0
	}

	// Peak concurrent connections (simplified - would need proper tracking in production)
	stats.PeakConcurrent = stats.ActiveWebsockets

	// Total connection attempts in period
	var totalAttempts int64
	if err := s.db.Model(&models.ActiveConnection{}).Where("connected_at >= ?", since).Count(&totalAttempts).Error; err != nil {
		return nil, fmt.Errorf("failed to count connection attempts: %w", err)
	}
	stats.TotalConnectionAttempts = int(totalAttempts)

	// Failed connections (simplified calculation)
	stats.FailedConnections = 0

	return stats, nil
}

// getSystemStats calculates system statistics
func (s *AdminService) getSystemStats() *models.SystemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := &models.SystemStats{
		UptimeHours:     1, // This would need to be tracked from server start
		MemoryUsageMB:   int(m.Alloc / 1024 / 1024),
		CPUUsagePercent: 0.0, // Would need proper CPU monitoring
		DiskUsageGB:     0.0, // Would need proper disk monitoring
	}

	return stats
}

// GetAllUsersForAdmin returns all users with admin-specific information
func (s *AdminService) GetAllUsersForAdmin(limit, offset int, statusFilter, sortBy string) ([]models.AdminUserInfo, int, error) {
	users, total, err := s.userService.GetAllUsers(limit, offset, statusFilter, sortBy)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get users: %w", err)
	}

	// Convert to admin user info
	var adminUsers []models.AdminUserInfo
	for _, user := range users {
		// Get additional admin-specific data
		activeChatsCount, _ := s.getActiveChatsCount(user.ID)
		totalMessagesSent, _ := s.getTotalMessagesSent(user.ID)

		// Prepare last seen
		var lastSeenStr *string
		if user.LastSeen != nil {
			lastSeenFormatted := user.LastSeen.Format(time.RFC3339)
			lastSeenStr = &lastSeenFormatted
		}

		adminUser := models.AdminUserInfo{
			ID:                user.ID.String(),
			Username:          user.Username,
			DisplayName:       user.DisplayName,
			Email:             user.Email,
			Status:            string(user.Status),
			LastSeen:          lastSeenStr,
			CreatedAt:         user.CreatedAt.Format(time.RFC3339),
			IsBlocked:         user.IsBlocked,
			ActiveChatsCount:  activeChatsCount,
			TotalMessagesSent: totalMessagesSent,
		}

		adminUsers = append(adminUsers, adminUser)
	}

	return adminUsers, total, nil
}

// BlockUserByAdmin blocks a user (admin function)
func (s *AdminService) BlockUserByAdmin(userID, adminID uuid.UUID, req *models.BlockUserRequest) (*models.BlockedUserInfo, error) {
	// Block the user
	blockedUser, err := s.userService.BlockUser(userID, adminID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to block user: %w", err)
	}

	// Disconnect user from WebSocket if online
	if s.wsManager != nil && s.wsManager.IsUserOnline(userID) {
		// Create notification message
		notificationData := map[string]interface{}{
			"type":          "account_blocked",
			"message":       "Your account has been blocked",
			"reason":        req.Reason,
			"description":   req.Description,
			"blocked_until": blockedUser.BlockedUntil,
		}

		// Send notification (this would need to be implemented differently)
		// For now, we'll just disconnect the user
		// connections := s.wsManager.GetUserConnections(userID)
		// for _, conn := range connections {
		//     conn.SendNotification("account_blocked", "Your account has been blocked", notificationData)
		//     conn.Close()
		// }

		// Update: Send notification through WebSocket manager
		notificationBytes, _ := json.Marshal(notificationData)
		s.wsManager.SendToUser(userID, notificationBytes)
	}

	// Update user status
	if err := s.userService.UpdateUserStatus(userID, models.StatusOfflineDisconnected); err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Warning: failed to update blocked user status: %v\n", err)
	}

	// Convert to response format
	var blockedUntilStr *string
	if blockedUser.BlockedUntil != nil {
		blockedUntilFormatted := blockedUser.BlockedUntil.Format(time.RFC3339)
		blockedUntilStr = &blockedUntilFormatted
	}

	blockedUserInfo := &models.BlockedUserInfo{
		ID:           blockedUser.User.ID.String(),
		Username:     blockedUser.User.Username,
		BlockedUntil: blockedUntilStr,
		Reason:       blockedUser.Reason,
		BlockedBy:    blockedUser.AdminUser.ID.String(),
		BlockedAt:    blockedUser.BlockedAt.Format(time.RFC3339),
	}

	return blockedUserInfo, nil
}

// UnblockUser unblocks a user (admin function)
func (s *AdminService) UnblockUser(userID, adminID uuid.UUID) error {
	// Update user blocked status
	if err := s.db.Model(&models.User{}).Where("id = ?", userID).Update("is_blocked", false).Error; err != nil {
		return fmt.Errorf("failed to unblock user: %w", err)
	}

	// Remove blocked user record
	if err := s.db.Where("user_id = ?", userID).Delete(&models.BlockedUser{}).Error; err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Warning: failed to remove blocked user record: %v\n", err)
	}

	return nil
}

// GetBlockedUsers returns all blocked users
func (s *AdminService) GetBlockedUsers() ([]models.BlockedUserInfo, error) {
	var blockedUsers []models.BlockedUser
	if err := s.db.Preload("User").Preload("AdminUser").Find(&blockedUsers).Error; err != nil {
		return nil, fmt.Errorf("failed to get blocked users: %w", err)
	}

	var result []models.BlockedUserInfo
	for _, blocked := range blockedUsers {
		var blockedUntilStr *string
		if blocked.BlockedUntil != nil {
			blockedUntilFormatted := blocked.BlockedUntil.Format(time.RFC3339)
			blockedUntilStr = &blockedUntilFormatted
		}

		info := models.BlockedUserInfo{
			ID:           blocked.User.ID.String(),
			Username:     blocked.User.Username,
			BlockedUntil: blockedUntilStr,
			Reason:       blocked.Reason,
			BlockedBy:    blocked.AdminUser.ID.String(),
			BlockedAt:    blocked.BlockedAt.Format(time.RFC3339),
		}

		result = append(result, info)
	}

	return result, nil
}

// CleanupExpiredBlocks removes expired user blocks
func (s *AdminService) CleanupExpiredBlocks() (int, error) {
	// Get expired blocks
	var expiredBlocks []models.BlockedUser
	now := time.Now()
	if err := s.db.Where("blocked_until IS NOT NULL AND blocked_until < ?", now).Find(&expiredBlocks).Error; err != nil {
		return 0, fmt.Errorf("failed to find expired blocks: %w", err)
	}

	if len(expiredBlocks) == 0 {
		return 0, nil
	}

	// Unblock users
	var unblocked int
	for _, block := range expiredBlocks {
		if err := s.UnblockUser(block.UserID, block.BlockedBy); err != nil {
			fmt.Printf("Warning: failed to unblock expired user %s: %v\n", block.UserID, err)
		} else {
			unblocked++
		}
	}

	return unblocked, nil
}

// Helper methods

// getActiveChatsCount returns the number of active chats for a user
func (s *AdminService) getActiveChatsCount(userID uuid.UUID) (int, error) {
	var count int64
	err := s.db.Model(&models.ChatMetadata{}).
		Where("user1_id = ? OR user2_id = ?", userID, userID).
		Count(&count).Error

	if err != nil {
		return 0, err
	}

	return int(count), nil
}

// getTotalMessagesSent returns the total number of messages sent by a user
func (s *AdminService) getTotalMessagesSent(userID uuid.UUID) (int, error) {
	var count int64
	err := s.db.Model(&models.PendingMessage{}).
		Where("sender_id = ?", userID).
		Count(&count).Error

	if err != nil {
		return 0, err
	}

	return int(count), nil
}

// IsUserAdmin checks if a user has admin privileges
func (s *AdminService) IsUserAdmin(userID uuid.UUID) (bool, error) {
	// Simplified implementation - in a real system, you'd have roles/permissions
	// For now, we'll consider the first user as admin or check against a config
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		return false, err
	}

	// Simple admin check - first registered user or specific username
	var firstUser models.User
	if err := s.db.Order("created_at ASC").First(&firstUser).Error; err != nil {
		return false, err
	}

	return user.ID == firstUser.ID, nil
}
