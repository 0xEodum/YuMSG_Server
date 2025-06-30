package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"gorm.io/gorm"

	"yumsg-server/internal/auth"
	"yumsg-server/internal/config"
	"yumsg-server/internal/interfaces"
	"yumsg-server/internal/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		// In production, implement proper origin checking
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// Client represents a WebSocket client connection
type Client struct {
	ID            string
	UserID        uuid.UUID
	Email         string
	Connection    *websocket.Conn
	Send          chan []byte
	Manager       *Manager
	LastHeartbeat time.Time
	IPAddress     string
	UserAgent     string
	mu            sync.RWMutex
}

// Manager manages WebSocket connections and message routing
type Manager struct {
	clients        map[string]*Client
	userClients    map[uuid.UUID]map[string]*Client // userID -> map of connectionID -> client
	register       chan *Client
	unregister     chan *Client
	broadcast      chan []byte
	userMessages   chan *UserMessage
	statusUpdates  chan *StatusUpdate
	mu             sync.RWMutex
	db             *gorm.DB
	userService    interfaces.UserServiceInterface
	messageService interfaces.MessageServiceInterface
	authService    *auth.AuthService
	config         *config.Config
	cleanup        *time.Ticker
}

// UserMessage represents a message to be sent to a specific user
type UserMessage struct {
	UserID  uuid.UUID
	Message []byte
}

// StatusUpdate represents a user status change to broadcast
type StatusUpdate struct {
	UserID     uuid.UUID
	Status     models.UserStatus
	LastSeen   *time.Time
	ExcludeIDs map[string]bool // Connection IDs to exclude from broadcast
}

// NewManager creates a new WebSocket manager
func NewManager(db *gorm.DB, userService interfaces.UserServiceInterface, messageService interfaces.MessageServiceInterface, authService *auth.AuthService, cfg *config.Config) *Manager {
	manager := &Manager{
		clients:        make(map[string]*Client),
		userClients:    make(map[uuid.UUID]map[string]*Client),
		register:       make(chan *Client),
		unregister:     make(chan *Client),
		broadcast:      make(chan []byte),
		userMessages:   make(chan *UserMessage),
		statusUpdates:  make(chan *StatusUpdate),
		db:             db,
		userService:    userService,
		messageService: messageService,
		authService:    authService,
		config:         cfg,
		cleanup:        time.NewTicker(time.Minute), // Cleanup every minute
	}

	go manager.run()
	go manager.cleanupInactiveConnections()

	return manager
}

// HandleWebSocket handles WebSocket connection upgrade and management
func (m *Manager) HandleWebSocket(c *gin.Context) {
	// Extract and validate JWT token
	token, err := m.authService.ExtractTokenFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_required",
			ErrorCode:        "MISSING_TOKEN",
			ErrorDescription: "WebSocket connection requires authentication",
		})
		return
	}

	claims, err := m.authService.ValidateToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Success:          false,
			Error:            "authentication_failed",
			ErrorCode:        "INVALID_TOKEN",
			ErrorDescription: "Invalid authentication token",
		})
		return
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Success:          false,
			Error:            "invalid_user",
			ErrorCode:        "INVALID_USER_ID",
			ErrorDescription: "Invalid user ID in token",
		})
		return
	}

	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// Create client
	client := &Client{
		ID:            uuid.New().String(),
		UserID:        userID,
		Email:         claims.Email,
		Connection:    conn,
		Send:          make(chan []byte, 256),
		Manager:       m,
		LastHeartbeat: time.Now(),
		IPAddress:     c.ClientIP(),
		UserAgent:     c.GetHeader("User-Agent"),
	}

	// Register client
	m.register <- client

	// Start goroutines
	go client.readPump()
	go client.writePump()
}

// run handles the main WebSocket manager loop
func (m *Manager) run() {
	for {
		select {
		case client := <-m.register:
			m.registerClient(client)

		case client := <-m.unregister:
			m.unregisterClient(client)

		case message := <-m.broadcast:
			m.broadcastToAllClients(message)

		case userMessage := <-m.userMessages:
			m.sendToUser(userMessage.UserID, userMessage.Message)

		case statusUpdate := <-m.statusUpdates:
			m.broadcastStatusUpdate(statusUpdate)
		}
	}
}

// registerClient registers a new WebSocket client
func (m *Manager) registerClient(client *Client) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to clients map
	m.clients[client.ID] = client

	// Add to user clients map
	if _, exists := m.userClients[client.UserID]; !exists {
		m.userClients[client.UserID] = make(map[string]*Client)
	}
	m.userClients[client.UserID][client.ID] = client

	log.Printf("Client registered: %s for user %s", client.ID, client.Email)

	// Update user status to online
	if err := m.userService.UpdateUserStatus(client.UserID, models.StatusOnline); err != nil {
		log.Printf("Failed to update user status to online: %v", err)
	}

	// Store connection in database
	m.storeConnection(client)

	// Send connection confirmation
	connectionMsg := models.WSMessage{
		EventType:  "CONNECTION_STATUS",
		Timestamp:  time.Now().Unix(),
		FromUserID: "server",
		Data:       m.marshalConnectionStatus(client.ID, "connected"),
	}

	if data, err := json.Marshal(connectionMsg); err == nil {
		select {
		case client.Send <- data:
		default:
			// Channel full, skip
		}
	}

	// Broadcast status update to other users
	m.broadcastUserStatusChange(client.UserID, models.StatusOnline, nil, map[string]bool{client.ID: true})

	// Send pending messages
	go m.deliverPendingMessages(client.UserID)
}

// unregisterClient unregisters a WebSocket client
func (m *Manager) unregisterClient(client *Client) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Remove from clients map
	if _, exists := m.clients[client.ID]; exists {
		delete(m.clients, client.ID)
		close(client.Send)
	}

	// Remove from user clients map
	if userClients, exists := m.userClients[client.UserID]; exists {
		delete(userClients, client.ID)

		// If no more connections for this user, update status
		if len(userClients) == 0 {
			delete(m.userClients, client.UserID)

			// Update user status to offline_disconnected
			if err := m.userService.UpdateUserStatus(client.UserID, models.StatusOfflineDisconnected); err != nil {
				log.Printf("Failed to update user status to offline: %v", err)
			}

			// Broadcast status update
			now := time.Now()
			m.broadcastUserStatusChange(client.UserID, models.StatusOfflineDisconnected, &now, nil)
		}
	}

	// Remove connection from database
	m.removeConnection(client)

	log.Printf("Client unregistered: %s for user %s", client.ID, client.Email)
}

// SendToUser sends a message to a specific user
func (m *Manager) SendToUser(userID uuid.UUID, message []byte) {
	select {
	case m.userMessages <- &UserMessage{UserID: userID, Message: message}:
	default:
		log.Printf("Failed to queue message for user %s: channel full", userID)
	}
}

// sendToUser implements sending message to user's active connections
func (m *Manager) sendToUser(userID uuid.UUID, message []byte) {
	m.mu.RLock()
	userClients, exists := m.userClients[userID]
	m.mu.RUnlock()

	if !exists {
		// User not connected, message will be stored as pending
		return
	}

	// Send to all user's active connections
	for _, client := range userClients {
		select {
		case client.Send <- message:
		default:
			// Channel full, close connection
			log.Printf("Client %s send channel full, closing connection", client.ID)
			close(client.Send)
			delete(m.clients, client.ID)
			delete(userClients, client.ID)
		}
	}
}

// BroadcastStatusUpdate broadcasts a user status change
func (m *Manager) BroadcastStatusUpdate(userID uuid.UUID, status models.UserStatus, lastSeen *time.Time, excludeConnections map[string]bool) {
	statusUpdate := &StatusUpdate{
		UserID:     userID,
		Status:     status,
		LastSeen:   lastSeen,
		ExcludeIDs: excludeConnections,
	}

	select {
	case m.statusUpdates <- statusUpdate:
	default:
		log.Printf("Failed to queue status update for user %s: channel full", userID)
	}
}

// broadcastStatusUpdate implements status broadcast to all relevant users
func (m *Manager) broadcastStatusUpdate(update *StatusUpdate) {
	// Since 1 server = 1 organization, all users can receive status updates
	// No need to filter by organization

	// Create status update message
	statusMsg := models.WSMessage{
		EventType:  "STATUS_UPDATE",
		Timestamp:  time.Now().Unix(),
		FromUserID: "server",
		Data:       m.marshalStatusUpdate(update.UserID.String(), string(update.Status), update.LastSeen),
	}

	messageData, err := json.Marshal(statusMsg)
	if err != nil {
		log.Printf("Failed to marshal status update: %v", err)
		return
	}

	// Send to all connected users (except excluded connections)
	m.mu.RLock()
	for _, clientMap := range m.userClients {
		for clientID, client := range clientMap {
			// Skip excluded connections
			if update.ExcludeIDs != nil && update.ExcludeIDs[clientID] {
				continue
			}

			// Skip same user
			if client.UserID == update.UserID {
				continue
			}

			select {
			case client.Send <- messageData:
			default:
				// Channel full, skip
			}
		}
	}
	m.mu.RUnlock()
}

// broadcastUserStatusChange is a helper for broadcasting status changes
func (m *Manager) broadcastUserStatusChange(userID uuid.UUID, status models.UserStatus, lastSeen *time.Time, excludeConnections map[string]bool) {
	m.BroadcastStatusUpdate(userID, status, lastSeen, excludeConnections)
}

// broadcastToAllClients sends a message to all connected clients
func (m *Manager) broadcastToAllClients(message []byte) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, client := range m.clients {
		select {
		case client.Send <- message:
		default:
			// Channel full, close connection
			close(client.Send)
			delete(m.clients, client.ID)
		}
	}
}

// GetUserConnections returns active connections for a user
func (m *Manager) GetUserConnections(userID uuid.UUID) []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userClients, exists := m.userClients[userID]
	if !exists {
		return nil
	}

	connections := make([]*Client, 0, len(userClients))
	for _, client := range userClients {
		connections = append(connections, client)
	}

	return connections
}

// IsUserOnline checks if a user has active WebSocket connections
func (m *Manager) IsUserOnline(userID uuid.UUID) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	userClients, exists := m.userClients[userID]
	return exists && len(userClients) > 0
}

// GetActiveConnectionsCount returns total number of active connections
func (m *Manager) GetActiveConnectionsCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.clients)
}

// GetActiveUsersCount returns number of users with active connections
func (m *Manager) GetActiveUsersCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.userClients)
}

// Helper methods for creating message data
func (m *Manager) marshalConnectionStatus(connectionID, status string) json.RawMessage {
	data := map[string]interface{}{
		"connection_id": connectionID,
		"status":        status,
	}
	bytes, _ := json.Marshal(data)
	return bytes
}

func (m *Manager) marshalStatusUpdate(userID, status string, lastSeen *time.Time) json.RawMessage {
	data := map[string]interface{}{
		"user_id": userID,
		"status":  status,
	}

	if lastSeen != nil {
		data["last_seen"] = lastSeen.Format(time.RFC3339)
	}

	bytes, _ := json.Marshal(data)
	return bytes
}

// Database operations
func (m *Manager) storeConnection(client *Client) {
	connection := &models.ActiveConnection{
		UserID:        client.UserID,
		ConnectionID:  client.ID,
		IPAddress:     client.IPAddress,
		UserAgent:     client.UserAgent,
		LastHeartbeat: client.LastHeartbeat,
	}

	if err := m.db.Create(connection).Error; err != nil {
		log.Printf("Failed to store connection in database: %v", err)
	}
}

func (m *Manager) removeConnection(client *Client) {
	if err := m.db.Where("connection_id = ?", client.ID).Delete(&models.ActiveConnection{}).Error; err != nil {
		log.Printf("Failed to remove connection from database: %v", err)
	}
}

func (m *Manager) updateConnectionHeartbeat(client *Client) {
	if err := m.db.Model(&models.ActiveConnection{}).
		Where("connection_id = ?", client.ID).
		Update("last_heartbeat", time.Now()).Error; err != nil {
		log.Printf("Failed to update connection heartbeat: %v", err)
	}
}

// Cleanup operations
func (m *Manager) cleanupInactiveConnections() {
	for range m.cleanup.C {
		m.performCleanup()
	}
}

func (m *Manager) performCleanup() {
	// Remove inactive connections from database
	cutoff := time.Now().Add(-m.config.Cleanup.InactiveConnectionAge)
	if err := m.db.Where("last_heartbeat < ?", cutoff).Delete(&models.ActiveConnection{}).Error; err != nil {
		log.Printf("Failed to cleanup inactive connections from database: %v", err)
	}

	// Check for stale WebSocket connections
	m.mu.RLock()
	staleClients := make([]*Client, 0)
	for _, client := range m.clients {
		if time.Since(client.LastHeartbeat) > m.config.App.WebSocket.ConnectionTimeout {
			staleClients = append(staleClients, client)
		}
	}
	m.mu.RUnlock()

	// Disconnect stale clients
	for _, client := range staleClients {
		log.Printf("Disconnecting stale client: %s", client.ID)
		client.Connection.Close()
	}
}

// deliverPendingMessages sends pending messages to newly connected user
func (m *Manager) deliverPendingMessages(userID uuid.UUID) {
	// Get pending messages
	messages, err := m.messageService.GetPendingMessages(userID, 100, nil)
	if err != nil {
		log.Printf("Failed to get pending messages for user %s: %v", userID, err)
		return
	}

	if len(messages) == 0 {
		return
	}

	// Send each message
	for _, msg := range messages {
		wsMessage := models.WSMessage{
			EventType:  "MESSAGE_RECEIVED",
			Timestamp:  msg.CreatedAt.Unix(),
			FromUserID: msg.SenderID.String(),
			Data:       m.marshalMessageReceived(msg.MessageType, msg.MessageData),
		}

		if data, err := json.Marshal(wsMessage); err == nil {
			m.SendToUser(userID, data)
		}
	}

	log.Printf("Delivered %d pending messages to user %s", len(messages), userID)
}

func (m *Manager) marshalMessageReceived(messageType string, messageData json.RawMessage) json.RawMessage {
	data := map[string]interface{}{
		"message_type": messageType,
		"message_data": messageData,
	}
	bytes, _ := json.Marshal(data)
	return bytes
}

// UpdateUserOfflineStatus updates user status to offline_connected
func (m *Manager) UpdateUserOfflineStatus(userID uuid.UUID, reason string) error {
	// Check if user has active connections
	if !m.IsUserOnline(userID) {
		return fmt.Errorf("user is not online")
	}

	// Update user status
	if err := m.userService.UpdateUserStatus(userID, models.StatusOfflineConnected); err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	// Broadcast status update
	m.broadcastUserStatusChange(userID, models.StatusOfflineConnected, nil, nil)

	return nil
}

// Close shuts down the WebSocket manager
func (m *Manager) Close() {
	m.cleanup.Stop()

	// Close all client connections
	m.mu.RLock()
	for _, client := range m.clients {
		client.Connection.Close()
		close(client.Send)
	}
	m.mu.RUnlock()
}
