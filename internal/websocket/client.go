package websocket

import (
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait
	pingPeriod = (pongWait * 9) / 10

	// Maximum message size allowed from peer
	maxMessageSize = 512
)

// IncomingMessage represents a message received from WebSocket client
type IncomingMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// PingMessage represents a ping message
type PingMessage struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// PongMessage represents a pong response
type PongMessage struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
}

// readPump pumps messages from the WebSocket connection to the hub
func (c *Client) readPump() {
	defer func() {
		c.Manager.unregister <- c
		c.Connection.Close()
	}()

	// Configure connection
	c.Connection.SetReadLimit(maxMessageSize)
	c.Connection.SetReadDeadline(time.Now().Add(pongWait))
	c.Connection.SetPongHandler(func(string) error {
		c.updateHeartbeat()
		c.Connection.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		// Read message
		_, messageBytes, err := c.Connection.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error for client %s: %v", c.ID, err)
			}
			break
		}

		// Update heartbeat
		c.updateHeartbeat()

		// Parse message
		var incomingMsg IncomingMessage
		if err := json.Unmarshal(messageBytes, &incomingMsg); err != nil {
			log.Printf("Failed to parse message from client %s: %v", c.ID, err)
			continue
		}

		// Handle message based on type
		c.handleMessage(&incomingMsg)
	}
}

// writePump pumps messages from the hub to the WebSocket connection
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Connection.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Connection.SetWriteDeadline(time.Now().Add(writeWait))

			if !ok {
				// Channel closed
				c.Connection.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			// Send message
			if err := c.Connection.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("Failed to write message to client %s: %v", c.ID, err)
				return
			}

		case <-ticker.C:
			c.Connection.SetWriteDeadline(time.Now().Add(writeWait))

			// Send ping
			pingMsg := PingMessage{
				Type:      "ping",
				Timestamp: time.Now().Unix(),
			}

			if pingData, err := json.Marshal(pingMsg); err == nil {
				if err := c.Connection.WriteMessage(websocket.TextMessage, pingData); err != nil {
					log.Printf("Failed to send ping to client %s: %v", c.ID, err)
					return
				}
			}
		}
	}
}

// handleMessage processes incoming messages from the client
func (c *Client) handleMessage(msg *IncomingMessage) {
	switch msg.Type {
	case "pong":
		c.handlePong(msg.Data)
	case "heartbeat":
		c.handleHeartbeat(msg.Data)
	case "typing_status":
		c.handleTypingStatus(msg.Data)
	case "message_acknowledgment":
		c.handleMessageAcknowledgment(msg.Data)
	default:
		log.Printf("Unknown message type from client %s: %s", c.ID, msg.Type)
	}
}

// handlePong handles pong response from client
func (c *Client) handlePong(data json.RawMessage) {
	var pongMsg PongMessage
	if err := json.Unmarshal(data, &pongMsg); err != nil {
		log.Printf("Failed to parse pong message from client %s: %v", c.ID, err)
		return
	}

	// Update heartbeat
	c.updateHeartbeat()

	// Optional: Calculate latency
	now := time.Now().Unix()
	latency := now - pongMsg.Timestamp

	log.Printf("Received pong from client %s, latency: %d seconds", c.ID, latency)
}

// handleHeartbeat handles heartbeat message from client
func (c *Client) handleHeartbeat(data json.RawMessage) {
	// Update heartbeat timestamp
	c.updateHeartbeat()

	// Update database
	c.Manager.updateConnectionHeartbeat(c)

	// Send heartbeat confirmation
	response := map[string]interface{}{
		"type":      "heartbeat_ack",
		"timestamp": time.Now().Unix(),
	}

	if responseData, err := json.Marshal(response); err == nil {
		select {
		case c.Send <- responseData:
		default:
			// Channel full
		}
	}
}

// handleTypingStatus handles typing status updates
func (c *Client) handleTypingStatus(data json.RawMessage) {
	var typingData struct {
		ChatUUID      string `json:"chat_uuid"`
		IsTyping      bool   `json:"is_typing"`
		TypingTimeout int    `json:"typing_timeout"`
		RecipientID   string `json:"recipient_id,omitempty"`
	}

	if err := json.Unmarshal(data, &typingData); err != nil {
		log.Printf("Failed to parse typing status from client %s: %v", c.ID, err)
		return
	}

	// Forward typing status to recipient if specified
	if typingData.RecipientID != "" {
		recipientUUID, err := parseUUID(typingData.RecipientID)
		if err != nil {
			log.Printf("Invalid recipient ID in typing status: %v", err)
			return
		}

		// Create typing status message for recipient
		typingMsg := map[string]interface{}{
			"event_type":   "TYPING_STATUS",
			"timestamp":    time.Now().Unix(),
			"from_user_id": c.UserID.String(),
			"data": map[string]interface{}{
				"chat_uuid":      typingData.ChatUUID,
				"is_typing":      typingData.IsTyping,
				"typing_timeout": typingData.TypingTimeout,
			},
		}

		if msgData, err := json.Marshal(typingMsg); err == nil {
			c.Manager.SendToUser(recipientUUID, msgData)
		}
	}
}

// handleMessageAcknowledgment handles message delivery acknowledgments
func (c *Client) handleMessageAcknowledgment(data json.RawMessage) {
	var ackData struct {
		MessageIDs []string `json:"message_ids"`
	}

	if err := json.Unmarshal(data, &ackData); err != nil {
		log.Printf("Failed to parse message acknowledgment from client %s: %v", c.ID, err)
		return
	}

	// Mark messages as delivered
	acknowledgedIDs, err := c.Manager.messageService.AcknowledgeMessages(c.UserID, ackData.MessageIDs)
	if err != nil {
		log.Printf("Failed to acknowledge messages for client %s: %v", c.ID, err)
		return
	}

	// Send acknowledgment confirmation
	response := map[string]interface{}{
		"type": "acknowledgment_confirmed",
		"data": map[string]interface{}{
			"acknowledged_ids": acknowledgedIDs,
			"acknowledged_at":  time.Now().Format(time.RFC3339),
		},
	}

	if responseData, err := json.Marshal(response); err == nil {
		select {
		case c.Send <- responseData:
		default:
			// Channel full
		}
	}
}

// updateHeartbeat updates the client's last heartbeat time
func (c *Client) updateHeartbeat() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.LastHeartbeat = time.Now()
}

// GetLastHeartbeat returns the last heartbeat time (thread-safe)
func (c *Client) GetLastHeartbeat() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.LastHeartbeat
}

// IsActive checks if the client connection is still active
func (c *Client) IsActive() bool {
	lastHeartbeat := c.GetLastHeartbeat()
	timeout := c.Manager.config.App.WebSocket.ConnectionTimeout
	return time.Since(lastHeartbeat) < timeout
}

// SendMessage sends a message to this client
func (c *Client) SendMessage(message []byte) error {
	select {
	case c.Send <- message:
		return nil
	default:
		return websocket.ErrCloseSent
	}
}

// SendPing sends a ping message to the client
func (c *Client) SendPing() error {
	pingMsg := PingMessage{
		Type:      "ping",
		Timestamp: time.Now().Unix(),
	}

	data, err := json.Marshal(pingMsg)
	if err != nil {
		return err
	}

	return c.SendMessage(data)
}

// Close gracefully closes the client connection
func (c *Client) Close() {
	// Close the send channel
	select {
	case <-c.Send:
		// Channel already closed
	default:
		close(c.Send)
	}

	// Close WebSocket connection
	c.Connection.Close()
}

// GetInfo returns client information
func (c *Client) GetInfo() map[string]interface{} {
	return map[string]interface{}{
		"id":             c.ID,
		"user_id":        c.UserID.String(),
		"username":       c.Username,
		"ip_address":     c.IPAddress,
		"user_agent":     c.UserAgent,
		"last_heartbeat": c.GetLastHeartbeat().Format(time.RFC3339),
		"is_active":      c.IsActive(),
	}
}

// SendConnectionStatus sends connection status update to client
func (c *Client) SendConnectionStatus(status string) {
	statusMsg := map[string]interface{}{
		"event_type":   "CONNECTION_STATUS",
		"timestamp":    time.Now().Unix(),
		"from_user_id": "server",
		"data": map[string]interface{}{
			"connection_id": c.ID,
			"status":        status,
		},
	}

	if data, err := json.Marshal(statusMsg); err == nil {
		c.SendMessage(data)
	}
}

// SendMessageReceived sends a received message notification to client
func (c *Client) SendMessageReceived(senderID, messageType string, messageData json.RawMessage) {
	msgReceived := map[string]interface{}{
		"event_type":   "MESSAGE_RECEIVED",
		"timestamp":    time.Now().Unix(),
		"from_user_id": senderID,
		"data": map[string]interface{}{
			"message_type": messageType,
			"message_data": messageData,
		},
	}

	if data, err := json.Marshal(msgReceived); err == nil {
		c.SendMessage(data)
	}
}

// SendStatusUpdate sends user status update to client
func (c *Client) SendStatusUpdate(userID, status string, lastSeen *time.Time) {
	statusData := map[string]interface{}{
		"user_id": userID,
		"status":  status,
	}

	if lastSeen != nil {
		statusData["last_seen"] = lastSeen.Format(time.RFC3339)
	}

	statusMsg := map[string]interface{}{
		"event_type":   "STATUS_UPDATE",
		"timestamp":    time.Now().Unix(),
		"from_user_id": "server",
		"data":         statusData,
	}

	if data, err := json.Marshal(statusMsg); err == nil {
		c.SendMessage(data)
	}
}

// SendNotification sends a server notification to client
func (c *Client) SendNotification(notificationType, message string, data interface{}) {
	notification := map[string]interface{}{
		"event_type":   "SERVER_NOTIFICATION",
		"timestamp":    time.Now().Unix(),
		"from_user_id": "server",
		"data": map[string]interface{}{
			"type":    notificationType,
			"message": message,
			"data":    data,
		},
	}

	if notificationData, err := json.Marshal(notification); err == nil {
		c.SendMessage(notificationData)
	}
}

// Helper function to parse UUID string
func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}
