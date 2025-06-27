package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"yumsg-server/internal/models"
)

var (
	ErrChatNotFound         = errors.New("chat not found")
	ErrRecipientNotFound    = errors.New("recipient not found")
	ErrRecipientBlocked     = errors.New("recipient is blocked")
	ErrInvalidMessageFormat = errors.New("invalid message format")
	ErrMessageNotFound      = errors.New("message not found")
)

// MessageService handles message and chat operations
type MessageService struct {
	db          *gorm.DB
	userService *UserService
}

// NewMessageService creates a new message service
func NewMessageService(db *gorm.DB, userService *UserService) *MessageService {
	return &MessageService{
		db:          db,
		userService: userService,
	}
}

// CreateChatMetadata creates metadata for a new chat between two users
func (s *MessageService) CreateChatMetadata(user1ID, user2ID uuid.UUID, chatUUID string) (*models.ChatMetadata, error) {
	// Ensure user1ID < user2ID for consistent storage
	if user1ID.String() > user2ID.String() {
		user1ID, user2ID = user2ID, user1ID
	}

	// Check if users exist
	if _, err := s.userService.GetUserByID(user1ID); err != nil {
		return nil, fmt.Errorf("user1 not found: %w", err)
	}
	if _, err := s.userService.GetUserByID(user2ID); err != nil {
		return nil, fmt.Errorf("user2 not found: %w", err)
	}

	// Check if chat metadata already exists
	var existingChat models.ChatMetadata
	err := s.db.Where("user1_id = ? AND user2_id = ?", user1ID, user2ID).First(&existingChat).Error
	if err == nil {
		// Chat already exists, update UUID
		existingChat.ChatUUID = chatUUID
		if err := s.db.Save(&existingChat).Error; err != nil {
			return nil, fmt.Errorf("failed to update chat metadata: %w", err)
		}
		return &existingChat, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("failed to check existing chat: %w", err)
	}

	// Create new chat metadata
	chatMetadata := &models.ChatMetadata{
		User1ID:  user1ID,
		User2ID:  user2ID,
		ChatUUID: chatUUID,
	}

	if err := s.db.Create(chatMetadata).Error; err != nil {
		return nil, fmt.Errorf("failed to create chat metadata: %w", err)
	}

	// Load users
	if err := s.db.Preload("User1").Preload("User2").First(chatMetadata, chatMetadata.ID).Error; err != nil {
		return nil, fmt.Errorf("failed to load chat metadata: %w", err)
	}

	return chatMetadata, nil
}

// DeleteChatMetadata removes chat metadata between two users
func (s *MessageService) DeleteChatMetadata(user1ID, user2ID uuid.UUID) error {
	// Ensure consistent order
	if user1ID.String() > user2ID.String() {
		user1ID, user2ID = user2ID, user1ID
	}

	result := s.db.Where("user1_id = ? AND user2_id = ?", user1ID, user2ID).Delete(&models.ChatMetadata{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete chat metadata: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrChatNotFound
	}

	return nil
}

// SendMessage sends a message to a recipient
func (s *MessageService) SendMessage(senderID, recipientID uuid.UUID, messageType string, messageData json.RawMessage) (*models.PendingMessage, string, error) {
	// Validate message type
	if !s.isValidMessageType(messageType) {
		return nil, "", ErrInvalidMessageFormat
	}

	// Check if recipient exists and is not blocked
	recipient, err := s.userService.GetUserByID(recipientID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, "", ErrRecipientNotFound
		}
		return nil, "", fmt.Errorf("failed to get recipient: %w", err)
	}

	if recipient.IsBlocked {
		return nil, "", ErrRecipientBlocked
	}

	// Create pending message
	pendingMessage := &models.PendingMessage{
		RecipientID: recipientID,
		SenderID:    senderID,
		MessageType: messageType,
		MessageData: messageData,
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	if err := s.db.Create(pendingMessage).Error; err != nil {
		return nil, "", fmt.Errorf("failed to create pending message: %w", err)
	}

	// Load sender information
	if err := s.db.Preload("Sender").Preload("Recipient").First(pendingMessage, pendingMessage.ID).Error; err != nil {
		return nil, "", fmt.Errorf("failed to load pending message: %w", err)
	}

	// Determine delivery status
	deliveryStatus := "queued_offline"
	if recipient.Status == models.StatusOnline {
		deliveryStatus = "sent"
	}

	return pendingMessage, deliveryStatus, nil
}

// GetPendingMessages retrieves pending messages for a user
func (s *MessageService) GetPendingMessages(userID uuid.UUID, limit int, since *time.Time) ([]models.PendingMessage, error) {
	query := s.db.Preload("Sender").Where("recipient_id = ? AND delivered = false", userID)

	if since != nil {
		query = query.Where("created_at > ?", *since)
	}

	var messages []models.PendingMessage
	if err := query.Order("created_at ASC").Limit(limit).Find(&messages).Error; err != nil {
		return nil, fmt.Errorf("failed to get pending messages: %w", err)
	}

	return messages, nil
}

// AcknowledgeMessages marks messages as delivered
func (s *MessageService) AcknowledgeMessages(userID uuid.UUID, messageIDs []string) ([]string, error) {
	var acknowledgedIDs []string

	// Convert string IDs to UUIDs
	var uuidIDs []uuid.UUID
	for _, idStr := range messageIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			continue // Skip invalid UUIDs
		}
		uuidIDs = append(uuidIDs, id)
	}

	// Update messages
	result := s.db.Model(&models.PendingMessage{}).
		Where("id IN ? AND recipient_id = ? AND delivered = false", uuidIDs, userID).
		Update("delivered", true)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to acknowledge messages: %w", result.Error)
	}

	// Get the IDs that were actually updated
	var updatedMessages []models.PendingMessage
	if err := s.db.Where("id IN ? AND recipient_id = ? AND delivered = true", uuidIDs, userID).
		Find(&updatedMessages).Error; err != nil {
		return nil, fmt.Errorf("failed to get acknowledged messages: %w", err)
	}

	for _, msg := range updatedMessages {
		acknowledgedIDs = append(acknowledgedIDs, msg.ID.String())
	}

	return acknowledgedIDs, nil
}

// CleanupExpiredMessages removes expired pending messages
func (s *MessageService) CleanupExpiredMessages() (int, error) {
	result := s.db.Where("expires_at < ?", time.Now()).Delete(&models.PendingMessage{})
	if result.Error != nil {
		return 0, fmt.Errorf("failed to cleanup expired messages: %w", result.Error)
	}

	return int(result.RowsAffected), nil
}

// GetChatMetadata retrieves chat metadata between two users
func (s *MessageService) GetChatMetadata(user1ID, user2ID uuid.UUID) (*models.ChatMetadata, error) {
	// Ensure consistent order
	if user1ID.String() > user2ID.String() {
		user1ID, user2ID = user2ID, user1ID
	}

	var chatMetadata models.ChatMetadata
	err := s.db.Preload("User1").Preload("User2").
		Where("user1_id = ? AND user2_id = ?", user1ID, user2ID).
		First(&chatMetadata).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrChatNotFound
		}
		return nil, fmt.Errorf("failed to get chat metadata: %w", err)
	}

	return &chatMetadata, nil
}

// GetUserChats retrieves all chat metadata for a user
func (s *MessageService) GetUserChats(userID uuid.UUID) ([]models.ChatMetadata, error) {
	var chats []models.ChatMetadata
	err := s.db.Preload("User1").Preload("User2").
		Where("user1_id = ? OR user2_id = ?", userID, userID).
		Order("created_at DESC").
		Find(&chats).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get user chats: %w", err)
	}

	return chats, nil
}

// GetMessageStats returns message statistics
func (s *MessageService) GetMessageStats(period time.Duration) (*models.MessageStats, error) {
	since := time.Now().Add(-period)

	var totalSent int64
	if err := s.db.Model(&models.PendingMessage{}).
		Where("created_at >= ?", since).
		Count(&totalSent).Error; err != nil {
		return nil, fmt.Errorf("failed to count total messages: %w", err)
	}

	var pendingDelivery int64
	if err := s.db.Model(&models.PendingMessage{}).
		Where("delivered = false AND expires_at > ?", time.Now()).
		Count(&pendingDelivery).Error; err != nil {
		return nil, fmt.Errorf("failed to count pending messages: %w", err)
	}

	hours := period.Hours()
	averagePerHour := float64(totalSent) / hours

	return &models.MessageStats{
		TotalSent:       int(totalSent),
		PendingDelivery: int(pendingDelivery),
		AveragePerHour:  averagePerHour,
	}, nil
}

// isValidMessageType validates message type
func (s *MessageService) isValidMessageType(messageType string) bool {
	validTypes := map[string]bool{
		"USER_MESSAGE":          true,
		"CHAT_INIT_REQUEST":     true,
		"CHAT_INIT_RESPONSE":    true,
		"CHAT_INIT_CONFIRM":     true,
		"CHAT_INIT_SIGNATURE":   true,
		"CHAT_REINIT_REQUEST":   true,
		"CHAT_REINIT_RESPONSE":  true,
		"CHAT_REINIT_CONFIRM":   true,
		"CHAT_REINIT_SIGNATURE": true,
		"CHAT_DELETE":           true,
		"TYPING_STATUS":         true,
	}

	return validTypes[messageType]
}

// GetPendingMessageCount returns the count of pending messages for a user
func (s *MessageService) GetPendingMessageCount(userID uuid.UUID) (int, error) {
	var count int64
	err := s.db.Model(&models.PendingMessage{}).
		Where("recipient_id = ? AND delivered = false AND expires_at > ?", userID, time.Now()).
		Count(&count).Error

	if err != nil {
		return 0, fmt.Errorf("failed to count pending messages: %w", err)
	}

	return int(count), nil
}

// MarkMessageAsDelivered marks a specific message as delivered
func (s *MessageService) MarkMessageAsDelivered(messageID uuid.UUID, userID uuid.UUID) error {
	result := s.db.Model(&models.PendingMessage{}).
		Where("id = ? AND recipient_id = ?", messageID, userID).
		Update("delivered", true)

	if result.Error != nil {
		return fmt.Errorf("failed to mark message as delivered: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrMessageNotFound
	}

	return nil
}

// DeletePendingMessage removes a specific pending message
func (s *MessageService) DeletePendingMessage(messageID uuid.UUID, userID uuid.UUID) error {
	result := s.db.Where("id = ? AND recipient_id = ?", messageID, userID).
		Delete(&models.PendingMessage{})

	if result.Error != nil {
		return fmt.Errorf("failed to delete pending message: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrMessageNotFound
	}

	return nil
}
