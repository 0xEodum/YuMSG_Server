package interfaces

import (
	"time"

	"yumsg-server/internal/models"

	"github.com/google/uuid"
)

// UserServiceInterface defines the interface for user service operations
type UserServiceInterface interface {
	GetUserByID(userID uuid.UUID) (*models.User, error)
	UpdateUserStatus(userID uuid.UUID, status models.UserStatus) error
	HasActiveChat(user1ID, user2ID uuid.UUID) (bool, error)
}

// MessageServiceInterface defines the interface for message service operations
type MessageServiceInterface interface {
	GetPendingMessages(userID uuid.UUID, limit int, since *time.Time) ([]models.PendingMessage, error)
	AcknowledgeMessages(userID uuid.UUID, messageIDs []string) ([]string, error)
	CleanupExpiredMessages() (int, error)
	GetMessageStats(period time.Duration) (*models.MessageStats, error)
}

// WebSocketManagerInterface defines the interface for WebSocket manager operations
type WebSocketManagerInterface interface {
	IsUserOnline(userID uuid.UUID) bool
	SendToUser(userID uuid.UUID, message []byte)
	GetActiveConnectionsCount() int
	GetActiveUsersCount() int
	UpdateUserOfflineStatus(userID uuid.UUID, reason string) error
	BroadcastStatusUpdate(userID uuid.UUID, status models.UserStatus, lastSeen *time.Time, excludeConnections map[string]bool)
	Close()
}

// ConnectionInfo represents connection information
type ConnectionInfo interface {
	GetID() string
	GetUserID() uuid.UUID
	GetLastHeartbeat() time.Time
	IsActive() bool
	SendMessage(message []byte) error
	Close()
}
