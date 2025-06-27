package models

import (
	"encoding/json"
)

// API Response wrappers
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

type ErrorResponse struct {
	Success          bool                `json:"success"`
	Error            string              `json:"error"`
	ErrorCode        string              `json:"error_code"`
	ErrorDescription string              `json:"error_description"`
	ValidationErrors map[string][]string `json:"validation_errors,omitempty"`
}

// Ping Response
type PingResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	Version    string `json:"version"`
	Timestamp  int64  `json:"timestamp"`
	ServerTime string `json:"server_time"`
}

// Organization Info Response
type OrganizationInfoResponse struct {
	Success      bool             `json:"success"`
	Organization OrganizationInfo `json:"organization"`
}

type OrganizationInfo struct {
	ID                  string              `json:"id"`
	Name                string              `json:"name"`
	Domain              string              `json:"domain"`
	SupportedAlgorithms SupportedAlgorithms `json:"supported_algorithms"`
	ServerPolicies      ServerPolicies      `json:"server_policies"`
}

type SupportedAlgorithms struct {
	Asymmetric []Algorithm `json:"asymmetric"`
	Symmetric  []Algorithm `json:"symmetric"`
	Signature  []Algorithm `json:"signature"`
}

type Algorithm struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	KeySize     int    `json:"key_size"`
	Recommended bool   `json:"recommended"`
}

type ServerPolicies struct {
	MaxFileSize                int `json:"max_file_size"`
	MessageRetentionDays       int `json:"message_retention_days"`
	MaxConcurrentConnections   int `json:"max_concurrent_connections"`
	RateLimitMessagesPerMinute int `json:"rate_limit_messages_per_minute"`
}

// Auth DTOs
type RegisterRequest struct {
	Username           string `json:"username" binding:"required,email"`
	Password           string `json:"password" binding:"required,min=8"`
	DisplayName        string `json:"display_name" binding:"required"`
	Email              string `json:"email" binding:"required,email"`
	OrganizationDomain string `json:"organization_domain" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	Success        bool               `json:"success"`
	Message        string             `json:"message"`
	Token          string             `json:"token,omitempty"`
	TokenExpiresAt string             `json:"token_expires_at,omitempty"`
	User           UserInfo           `json:"user"`
	Organization   *OrganizationBrief `json:"organization,omitempty"`
}

type UserInfo struct {
	ID          string  `json:"id"`
	Username    string  `json:"username"`
	DisplayName string  `json:"display_name"`
	Email       string  `json:"email"`
	Status      string  `json:"status"`
	LastSeen    *string `json:"last_seen"`
	CreatedAt   string  `json:"created_at"`
}

type OrganizationBrief struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

// User DTOs
type UserProfileResponse struct {
	Success bool                `json:"success"`
	User    DetailedUserProfile `json:"user"`
}

type DetailedUserProfile struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	DisplayName  string            `json:"display_name"`
	Email        string            `json:"email"`
	Status       string            `json:"status"`
	LastSeen     *string           `json:"last_seen"`
	CreatedAt    string            `json:"created_at"`
	Organization OrganizationBrief `json:"organization"`
	Preferences  UserPreferences   `json:"preferences"`
}

type UpdateProfileRequest struct {
	DisplayName string          `json:"display_name"`
	Email       string          `json:"email" binding:"omitempty,email"`
	Preferences UserPreferences `json:"preferences"`
}

type UserSearchResponse struct {
	Success    bool               `json:"success"`
	Query      string             `json:"query"`
	TotalFound int                `json:"total_found"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
	Users      []SearchUserResult `json:"users"`
}

type SearchUserResult struct {
	ID            string  `json:"id"`
	Username      string  `json:"username"`
	DisplayName   string  `json:"display_name"`
	Status        string  `json:"status"`
	LastSeen      *string `json:"last_seen"`
	HasActiveChat bool    `json:"has_active_chat"`
}

type UserStatusResponse struct {
	Success bool           `json:"success"`
	User    UserStatusInfo `json:"user"`
}

type UserStatusInfo struct {
	ID             string         `json:"id"`
	Username       string         `json:"username"`
	DisplayName    string         `json:"display_name"`
	Status         string         `json:"status"`
	LastSeen       *string        `json:"last_seen"`
	ConnectionInfo ConnectionInfo `json:"connection_info"`
}

type ConnectionInfo struct {
	ConnectedAt  string `json:"connected_at"`
	LastActivity string `json:"last_activity"`
}

// Chat DTOs
type CreateChatRequest struct {
	RecipientID string `json:"recipient_id" binding:"required,uuid"`
	ChatUUID    string `json:"chat_uuid" binding:"required"`
}

type ChatResponse struct {
	Success bool     `json:"success"`
	Message string   `json:"message"`
	Chat    ChatInfo `json:"chat"`
}

type ChatInfo struct {
	ID           string     `json:"id"`
	ChatUUID     string     `json:"chat_uuid"`
	Participants []UserInfo `json:"participants"`
	CreatedAt    string     `json:"created_at"`
}

type DeleteChatResponse struct {
	Success             bool                `json:"success"`
	Message             string              `json:"message"`
	DeletedChatMetadata DeletedChatMetadata `json:"deleted_chat_metadata"`
}

type DeletedChatMetadata struct {
	Participants []string `json:"participants"`
	DeletedAt    string   `json:"deleted_at"`
}

// Presence DTOs
type SetOfflineRequest struct {
	Reason string `json:"reason" binding:"required,oneof=user_initiated away busy do_not_disturb"`
}

type PresenceResponse struct {
	Success    bool           `json:"success"`
	Message    string         `json:"message"`
	UserStatus UserStatusInfo `json:"user_status"`
}

// Message DTOs
type SendMessageRequest struct {
	MessageType string          `json:"message_type" binding:"required"`
	MessageData json.RawMessage `json:"message_data" binding:"required"`
}

type SendMessageResponse struct {
	Success        bool   `json:"success"`
	MessageID      string `json:"message_id"`
	Timestamp      int64  `json:"timestamp"`
	DeliveryStatus string `json:"delivery_status"`
}

type PendingMessagesResponse struct {
	Success      bool             `json:"success"`
	TotalPending int              `json:"total_pending"`
	Messages     []PendingMessage `json:"messages"`
}

type AcknowledgeRequest struct {
	MessageIDs []string `json:"message_ids" binding:"required"`
}

type AcknowledgeResponse struct {
	Success           bool     `json:"success"`
	Message           string   `json:"message"`
	AcknowledgedCount int      `json:"acknowledged_count"`
	AcknowledgedIDs   []string `json:"acknowledged_ids"`
	AcknowledgedAt    string   `json:"acknowledged_at"`
}

// WebSocket Message Types
type WSMessage struct {
	EventType  string          `json:"event_type"`
	Timestamp  int64           `json:"timestamp"`
	FromUserID string          `json:"from_user_id"`
	Data       json.RawMessage `json:"data"`
}

type WSMessageReceived struct {
	MessageType string          `json:"message_type"`
	MessageData json.RawMessage `json:"message_data"`
}

type WSStatusUpdate struct {
	UserID   string  `json:"user_id"`
	Status   string  `json:"status"`
	LastSeen *string `json:"last_seen"`
}

type WSConnectionStatus struct {
	ConnectionID string `json:"connection_id"`
	Status       string `json:"status"`
}

// Admin DTOs
type AdminUsersResponse struct {
	Success    bool            `json:"success"`
	TotalUsers int             `json:"total_users"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	Users      []AdminUserInfo `json:"users"`
}

type AdminUserInfo struct {
	ID                string  `json:"id"`
	Username          string  `json:"username"`
	DisplayName       string  `json:"display_name"`
	Email             string  `json:"email"`
	Status            string  `json:"status"`
	LastSeen          *string `json:"last_seen"`
	CreatedAt         string  `json:"created_at"`
	IsBlocked         bool    `json:"is_blocked"`
	ActiveChatsCount  int     `json:"active_chats_count"`
	TotalMessagesSent int     `json:"total_messages_sent"`
}

type BlockUserRequest struct {
	Reason        string `json:"reason" binding:"required"`
	Description   string `json:"description"`
	DurationHours int    `json:"duration_hours"`
	NotifyUser    bool   `json:"notify_user"`
}

type BlockUserResponse struct {
	Success     bool            `json:"success"`
	Message     string          `json:"message"`
	BlockedUser BlockedUserInfo `json:"blocked_user"`
}

type BlockedUserInfo struct {
	ID           string  `json:"id"`
	Username     string  `json:"username"`
	BlockedUntil *string `json:"blocked_until"`
	Reason       string  `json:"reason"`
	BlockedBy    string  `json:"blocked_by"`
	BlockedAt    string  `json:"blocked_at"`
}

type StatsResponse struct {
	Success     bool        `json:"success"`
	Period      string      `json:"period"`
	Stats       ServerStats `json:"stats"`
	GeneratedAt string      `json:"generated_at"`
}

type ServerStats struct {
	Users       UserStats       `json:"users"`
	Messages    MessageStats    `json:"messages"`
	Connections ConnectionStats `json:"connections"`
	Server      SystemStats     `json:"server"`
}

type UserStats struct {
	Total               int `json:"total"`
	Online              int `json:"online"`
	OfflineConnected    int `json:"offline_connected"`
	OfflineDisconnected int `json:"offline_disconnected"`
	Blocked             int `json:"blocked"`
	NewRegistrations    int `json:"new_registrations"`
}

type MessageStats struct {
	TotalSent       int     `json:"total_sent"`
	PendingDelivery int     `json:"pending_delivery"`
	AveragePerHour  float64 `json:"average_per_hour"`
}

type ConnectionStats struct {
	ActiveWebsockets        int `json:"active_websockets"`
	PeakConcurrent          int `json:"peak_concurrent"`
	TotalConnectionAttempts int `json:"total_connection_attempts"`
	FailedConnections       int `json:"failed_connections"`
}

type SystemStats struct {
	UptimeHours     int     `json:"uptime_hours"`
	MemoryUsageMB   int     `json:"memory_usage_mb"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	DiskUsageGB     float64 `json:"disk_usage_gb"`
}
