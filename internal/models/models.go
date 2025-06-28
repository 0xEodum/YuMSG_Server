package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// UserStatus represents user online status
type UserStatus string

const (
	StatusOnline              UserStatus = "online"
	StatusOfflineConnected    UserStatus = "offline_connected"
	StatusOfflineDisconnected UserStatus = "offline_disconnected"
)

// User represents a user entity
type User struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	Username     string     `json:"username" gorm:"type:varchar(255);unique;not null"`
	Email        string     `json:"email" gorm:"type:varchar(255)"`
	PasswordHash string     `json:"-" gorm:"type:varchar(255);not null"`
	DisplayName  string     `json:"display_name" gorm:"type:varchar(255)"`
	Status       UserStatus `json:"status" gorm:"type:varchar(30);default:'offline_disconnected'"`
	LastSeen     *time.Time `json:"last_seen" gorm:"type:timestamp with time zone"`
	CreatedAt    time.Time  `json:"created_at" gorm:"default:now()"`
	UpdatedAt    time.Time  `json:"updated_at" gorm:"default:now()"`
	IsBlocked    bool       `json:"is_blocked" gorm:"default:false"`
}

// ActiveConnection represents an active WebSocket connection
type ActiveConnection struct {
	ID            uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID        uuid.UUID `json:"user_id" gorm:"type:uuid;not null"`
	ConnectionID  string    `json:"connection_id" gorm:"type:varchar(255);unique;not null"`
	ConnectedAt   time.Time `json:"connected_at" gorm:"default:now()"`
	LastHeartbeat time.Time `json:"last_heartbeat" gorm:"default:now()"`
	IPAddress     string    `json:"ip_address" gorm:"type:inet"`
	UserAgent     string    `json:"user_agent" gorm:"type:text"`

	// Relations
	User User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// ChatMetadata represents chat metadata (only relationships between users)
type ChatMetadata struct {
	ID        uuid.UUID `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	User1ID   uuid.UUID `json:"user1_id" gorm:"type:uuid;not null"`
	User2ID   uuid.UUID `json:"user2_id" gorm:"type:uuid;not null"`
	ChatUUID  string    `json:"chat_uuid" gorm:"type:varchar(255)"`
	CreatedAt time.Time `json:"created_at" gorm:"default:now()"`

	// Relations
	User1 User `json:"user1,omitempty" gorm:"foreignKey:User1ID"`
	User2 User `json:"user2,omitempty" gorm:"foreignKey:User2ID"`
}

// PendingMessage represents an offline message waiting for delivery
type PendingMessage struct {
	ID          uuid.UUID       `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	RecipientID uuid.UUID       `json:"recipient_id" gorm:"type:uuid;not null"`
	SenderID    uuid.UUID       `json:"sender_id" gorm:"type:uuid;not null"`
	MessageType string          `json:"message_type" gorm:"type:varchar(50);not null"`
	MessageData json.RawMessage `json:"message_data" gorm:"type:jsonb;not null"`
	CreatedAt   time.Time       `json:"created_at" gorm:"default:now()"`
	ExpiresAt   time.Time       `json:"expires_at" gorm:"default:now() + interval '7 days'"`
	Delivered   bool            `json:"delivered" gorm:"default:false"`

	// Relations
	Recipient User `json:"recipient,omitempty" gorm:"foreignKey:RecipientID"`
	Sender    User `json:"sender,omitempty" gorm:"foreignKey:SenderID"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        uuid.UUID       `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID    *uuid.UUID      `json:"user_id" gorm:"type:uuid"`
	Action    string          `json:"action" gorm:"type:varchar(100);not null"`
	Details   json.RawMessage `json:"details" gorm:"type:jsonb"`
	IPAddress string          `json:"ip_address" gorm:"type:inet"`
	CreatedAt time.Time       `json:"created_at" gorm:"default:now()"`

	// Relations
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// UserPreferences represents user crypto algorithm preferences
type UserPreferences struct {
	SelectedAlgorithms AlgorithmSelection `json:"selected_algorithms"`
}

// AlgorithmSelection represents selected cryptographic algorithms
type AlgorithmSelection struct {
	Asymmetric string `json:"asymmetric"`
	Symmetric  string `json:"symmetric"`
	Signature  string `json:"signature"`
}

// BlockedUser represents a blocked user record
type BlockedUser struct {
	ID           uuid.UUID  `json:"id" gorm:"type:uuid;primary_key;default:gen_random_uuid()"`
	UserID       uuid.UUID  `json:"user_id" gorm:"type:uuid;not null"`
	BlockedBy    uuid.UUID  `json:"blocked_by" gorm:"type:uuid;not null"`
	Reason       string     `json:"reason" gorm:"type:varchar(100)"`
	Description  string     `json:"description" gorm:"type:text"`
	BlockedUntil *time.Time `json:"blocked_until" gorm:"type:timestamp with time zone"`
	BlockedAt    time.Time  `json:"blocked_at" gorm:"default:now()"`

	// Relations
	User      User `json:"user,omitempty" gorm:"foreignKey:UserID"`
	AdminUser User `json:"admin_user,omitempty" gorm:"foreignKey:BlockedBy"`
}
