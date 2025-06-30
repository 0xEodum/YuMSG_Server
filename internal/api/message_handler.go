package api

import (
	"encoding/json"
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

// MessageHandler handles message-related HTTP requests
type MessageHandler struct {
	messageService *services.MessageService
	userService    *services.UserService
	wsManager      interfaces.WebSocketManagerInterface
}

// NewMessageHandler creates a new message handler
func NewMessageHandler(messageService *services.MessageService, userService *services.UserService, wsManager interfaces.WebSocketManagerInterface) *MessageHandler {
	return &MessageHandler{
		messageService: messageService,
		userService:    userService,
		wsManager:      wsManager,
	}
}

// SendMessage sends a message to a recipient
// POST /api/messages/{recipientId}
func (h *MessageHandler) SendMessage(c *gin.Context) {
	senderID, err := auth.GetUserIDFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_USER_ID",
			ErrorDescription: "User ID not found in token",
		})
		return
	}

	recipientIDParam := c.Param("recipientId")
	recipientID, err := uuid.Parse(recipientIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_recipient",
			ErrorCode:        "INVALID_RECIPIENT_ID",
			ErrorDescription: "Invalid recipient ID format",
		})
		return
	}

	var req models.SendMessageRequest
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

	// Since 1 server = 1 organization, no need to verify organizations
	// All users on this server belong to the same organization

	// Send message
	pendingMessage, deliveryStatus, err := h.messageService.SendMessage(senderID, recipientID, req.MessageType, req.MessageData)
	if err != nil {
		errorCode, statusCode := h.mapMessageError(err)

		c.JSON(statusCode, models.ErrorResponse{
			Success:          false,
			Error:            errorCode,
			ErrorCode:        errorCode,
			ErrorDescription: err.Error(),
		})
		return
	}

	// If recipient is online, send via WebSocket
	if h.wsManager.IsUserOnline(recipientID) {
		wsMessage := models.WSMessage{
			EventType:  "MESSAGE_RECEIVED",
			Timestamp:  time.Now().Unix(),
			FromUserID: senderID.String(),
			Data:       h.createMessageReceivedData(req.MessageType, req.MessageData),
		}

		if wsData, err := json.Marshal(wsMessage); err == nil {
			h.wsManager.SendToUser(recipientID, wsData)
		}
	}

	response := models.SendMessageResponse{
		Success:        true,
		MessageID:      pendingMessage.ID.String(),
		Timestamp:      time.Now().Unix(),
		DeliveryStatus: deliveryStatus,
	}

	c.JSON(http.StatusOK, response)
}

// GetPendingMessages retrieves pending messages for the current user
// GET /api/messages/pending
func (h *MessageHandler) GetPendingMessages(c *gin.Context) {
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

	// Parse query parameters
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	sinceParam := c.Query("since")

	// Validate limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	// Parse since timestamp if provided
	var since *time.Time
	if sinceParam != "" {
		if sinceTimestamp, err := strconv.ParseInt(sinceParam, 10, 64); err == nil {
			sinceTime := time.Unix(sinceTimestamp/1000, 0) // Assuming milliseconds
			since = &sinceTime
		}
	}

	// Get pending messages
	messages, err := h.messageService.GetPendingMessages(userID, limit, since)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve pending messages",
		})
		return
	}

	// Convert to response format
	var responseMessages []models.PendingMessage
	for _, msg := range messages {
		// Ensure sender information is loaded
		senderName := "Unknown"
		if msg.Sender.DisplayName != "" {
			senderName = msg.Sender.DisplayName
		}

		responseMsg := models.PendingMessage{
			ID:          msg.ID,
			RecipientID: msg.RecipientID,
			SenderID:    msg.SenderID,
			MessageType: msg.MessageType,
			MessageData: msg.MessageData,
			CreatedAt:   msg.CreatedAt,
			ExpiresAt:   msg.ExpiresAt,
			Delivered:   msg.Delivered,
		}

		// Add sender info to response
		responseMsg.Sender.ID = msg.SenderID
		responseMsg.Sender.DisplayName = senderName

		responseMessages = append(responseMessages, responseMsg)
	}

	response := models.PendingMessagesResponse{
		Success:      true,
		TotalPending: len(responseMessages),
		Messages:     responseMessages,
	}

	c.JSON(http.StatusOK, response)
}

// AcknowledgeMessages marks messages as delivered
// POST /api/messages/acknowledge
func (h *MessageHandler) AcknowledgeMessages(c *gin.Context) {
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

	var req models.AcknowledgeRequest
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

	// Acknowledge messages
	acknowledgedIDs, err := h.messageService.AcknowledgeMessages(userID, req.MessageIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "ACKNOWLEDGE_FAILED",
			ErrorDescription: "Failed to acknowledge messages",
		})
		return
	}

	response := models.AcknowledgeResponse{
		Success:           true,
		Message:           "Сообщения помечены как доставленные",
		AcknowledgedCount: len(acknowledgedIDs),
		AcknowledgedIDs:   acknowledgedIDs,
		AcknowledgedAt:    time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

// CreateChat creates metadata for a new chat
// POST /api/chats
func (h *MessageHandler) CreateChat(c *gin.Context) {
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

	var req models.CreateChatRequest
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

	recipientID, err := uuid.Parse(req.RecipientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_recipient",
			ErrorCode:        "INVALID_RECIPIENT_ID",
			ErrorDescription: "Invalid recipient ID format",
		})
		return
	}

	// Since 1 server = 1 organization, no need to verify organizations
	// All users on this server belong to the same organization

	// Create chat metadata
	chatMetadata, err := h.messageService.CreateChatMetadata(currentUserID, recipientID, req.ChatUUID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "chat_creation_failed",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to create chat metadata",
		})
		return
	}

	// Prepare participants
	participants := []models.UserInfo{
		{
			ID:          chatMetadata.User1.ID.String(),
			DisplayName: chatMetadata.User1.DisplayName,
			Email:       chatMetadata.User1.Email,
		},
		{
			ID:          chatMetadata.User2.ID.String(),
			DisplayName: chatMetadata.User2.DisplayName,
			Email:       chatMetadata.User2.Email,
		},
	}

	response := models.ChatResponse{
		Success: true,
		Message: "Метаданные чата созданы",
		Chat: models.ChatInfo{
			ID:           chatMetadata.ID.String(),
			ChatUUID:     chatMetadata.ChatUUID,
			Participants: participants,
			CreatedAt:    chatMetadata.CreatedAt.Format(time.RFC3339),
		},
	}

	c.JSON(http.StatusOK, response)
}

// DeleteChat removes chat metadata
// DELETE /api/chats/{recipientId}
func (h *MessageHandler) DeleteChat(c *gin.Context) {
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

	recipientIDParam := c.Param("recipientId")
	recipientID, err := uuid.Parse(recipientIDParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_recipient",
			ErrorCode:        "INVALID_RECIPIENT_ID",
			ErrorDescription: "Invalid recipient ID format",
		})
		return
	}

	// Get chat metadata before deletion for notification
	chatMetadata, err := h.messageService.GetChatMetadata(currentUserID, recipientID)
	if err != nil {
		if errors.Is(err, services.ErrChatNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Success:          false,
				Error:            "chat_not_found",
				ErrorCode:        "CHAT_NOT_FOUND",
				ErrorDescription: "Chat not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to get chat metadata",
		})
		return
	}

	// Send CHAT_DELETE message to recipient first
	deleteMessageData := map[string]interface{}{
		"chat_uuid":     chatMetadata.ChatUUID,
		"delete_reason": "user_initiated",
	}

	deleteMessageBytes, _ := json.Marshal(deleteMessageData)
	_, _, err = h.messageService.SendMessage(currentUserID, recipientID, "CHAT_DELETE", deleteMessageBytes)
	if err != nil {
		// Log error but continue with deletion
		// log.Printf("Failed to send chat delete message: %v", err)
	}

	// Delete chat metadata
	err = h.messageService.DeleteChatMetadata(currentUserID, recipientID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "deletion_failed",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to delete chat metadata",
		})
		return
	}

	response := models.DeleteChatResponse{
		Success: true,
		Message: "Метаданные чата удалены",
		DeletedChatMetadata: models.DeletedChatMetadata{
			Participants: []string{currentUserID.String(), recipientID.String()},
			DeletedAt:    time.Now().Format(time.RFC3339),
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetUserChats returns all chat metadata for the current user
// GET /api/chats
func (h *MessageHandler) GetUserChats(c *gin.Context) {
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

	chats, err := h.messageService.GetUserChats(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to get user chats",
		})
		return
	}

	// Convert to response format
	var chatInfos []models.ChatInfo
	for _, chat := range chats {
		participants := []models.UserInfo{
			{
				ID:          chat.User1.ID.String(),
				DisplayName: chat.User1.DisplayName,
				Email:       chat.User1.Email,
			},
			{
				ID:          chat.User2.ID.String(),
				DisplayName: chat.User2.DisplayName,
				Email:       chat.User2.Email,
			},
		}

		chatInfos = append(chatInfos, models.ChatInfo{
			ID:           chat.ID.String(),
			ChatUUID:     chat.ChatUUID,
			Participants: participants,
			CreatedAt:    chat.CreatedAt.Format(time.RFC3339),
		})
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"success": true,
		"chats":   chatInfos,
		"total":   len(chatInfos),
	})
}

// Helper methods

// Note: verifyUsersInSameOrganization is no longer needed since 1 server = 1 organization
// All users on this server belong to the same organization by design

// mapMessageError maps service errors to HTTP error codes
func (h *MessageHandler) mapMessageError(err error) (string, int) {
	switch {
	case errors.Is(err, services.ErrRecipientNotFound):
		return "recipient_not_found", http.StatusNotFound
	case errors.Is(err, services.ErrRecipientBlocked):
		return "recipient_blocked", http.StatusForbidden
	case errors.Is(err, services.ErrInvalidMessageFormat):
		return "invalid_message_format", http.StatusBadRequest
	case errors.Is(err, services.ErrChatNotFound):
		return "chat_not_found", http.StatusNotFound
	default:
		return "server_error", http.StatusInternalServerError
	}
}

// createMessageReceivedData creates WebSocket message data
func (h *MessageHandler) createMessageReceivedData(messageType string, messageData json.RawMessage) json.RawMessage {
	data := map[string]interface{}{
		"message_type": messageType,
		"message_data": messageData,
	}
	bytes, _ := json.Marshal(data)
	return bytes
}
