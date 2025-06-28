package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"yumsg-server/internal/api"
	"yumsg-server/internal/auth"
	"yumsg-server/internal/config"
	"yumsg-server/internal/database"
	"yumsg-server/internal/services"
	"yumsg-server/internal/websocket"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set Gin mode based on environment
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize database
	db, err := database.NewDatabase(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Run database migrations
	if err := db.AutoMigrate(); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	// Initialize services
	authService := auth.NewAuthService(cfg)
	organizationService := services.NewOrganizationService(db.DB, cfg)
	userService := services.NewUserService(db.DB, authService)
	messageService := services.NewMessageService(db.DB, userService)

	// Initialize WebSocket manager (using interfaces to break circular dependency)
	wsManager := websocket.NewManager(db.DB, userService, messageService, authService, cfg)

	// Initialize admin service and set WebSocket manager
	adminService := services.NewAdminService(db.DB, userService, messageService)
	adminService.SetWebSocketManager(wsManager)

	// Initialize HTTP handlers
	authHandler := api.NewAuthHandler(userService, authService)
	userHandler := api.NewUserHandler(userService, messageService, wsManager)
	messageHandler := api.NewMessageHandler(messageService, userService, wsManager)
	organizationHandler := api.NewOrganizationHandler(organizationService)
	adminHandler := api.NewAdminHandler(adminService, userService)

	// Initialize Gin router
	router := gin.New()

	// Add middleware
	router.Use(gin.Logger())
	router.Use(gin.Recovery())
	router.Use(corsMiddleware())

	// Setup routes
	setupRoutes(router, authHandler, userHandler, messageHandler, organizationHandler, adminHandler, authService, wsManager)

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.GetServerAddress(),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start cleanup service
	go startCleanupService(cfg, messageService, adminService)

	// Start server in a goroutine
	go func() {
		log.Printf("Starting YuMSG server on %s", cfg.GetServerAddress())
		log.Printf("Environment: %s", cfg.App.Environment)
		log.Printf("Version: %s", cfg.App.Version)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown WebSocket manager
	wsManager.Close()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// setupRoutes configures all HTTP routes
func setupRoutes(
	router *gin.Engine,
	authHandler *api.AuthHandler,
	userHandler *api.UserHandler,
	messageHandler *api.MessageHandler,
	organizationHandler *api.OrganizationHandler,
	adminHandler *api.AdminHandler,
	authService *auth.AuthService,
	wsManager *websocket.Manager,
) {
	// API v1 group
	v1 := router.Group("/api")

	// Public endpoints
	v1.GET("/ping", authHandler.HealthCheck)
	v1.GET("/organization/info", organizationHandler.GetOrganizationInfo)
	v1.POST("/auth/register", authHandler.Register)
	v1.POST("/auth/login", authHandler.Login)

	// WebSocket endpoint (requires auth)
	v1.GET("/ws/messages", wsManager.HandleWebSocket)

	// Protected endpoints (require JWT)
	protected := v1.Group("/")
	protected.Use(authService.AuthMiddleware())
	{
		// User management
		protected.GET("/users/profile", userHandler.GetProfile)
		protected.PUT("/users/profile", userHandler.UpdateProfile)
		protected.GET("/users/search", userHandler.SearchUsers)
		protected.GET("/users/:userId/status", userHandler.GetUserStatus)
		protected.GET("/users/online", userHandler.GetOnlineUsers)

		// Presence management
		protected.POST("/presence/offline", userHandler.SetOfflineStatus)

		// Chat management
		protected.POST("/chats", messageHandler.CreateChat)
		protected.DELETE("/chats/:recipientId", messageHandler.DeleteChat)
		protected.GET("/chats", messageHandler.GetUserChats)

		// Message management
		protected.POST("/messages/:recipientId", messageHandler.SendMessage)
		protected.GET("/messages/pending", messageHandler.GetPendingMessages)
		protected.POST("/messages/acknowledge", messageHandler.AcknowledgeMessages)

		// Auth management
		protected.GET("/auth/validate", authHandler.ValidateToken)
		protected.POST("/auth/logout", authHandler.Logout)
	}

	// Admin endpoints (require JWT + admin privileges)
	admin := v1.Group("/admin")
	admin.Use(authService.AuthMiddleware())
	admin.Use(adminHandler.AdminMiddleware())
	{
		admin.GET("/users", adminHandler.GetAllUsers)
		admin.POST("/users/:id/block", adminHandler.BlockUser)
		admin.POST("/users/:id/unblock", adminHandler.UnblockUser)
		admin.GET("/stats", adminHandler.GetServerStats)
		admin.GET("/blocked-users", adminHandler.GetBlockedUsers)
		admin.POST("/cleanup/expired-blocks", adminHandler.CleanupExpiredBlocks)
		admin.GET("/health", adminHandler.GetSystemHealth)
		admin.GET("/audit-logs", adminHandler.GetAuditLogs)
	}

	// Additional organization endpoints (admin only) - only stats for now
	orgAdmin := v1.Group("/organizations")
	orgAdmin.Use(authService.AuthMiddleware())
	orgAdmin.Use(adminHandler.AdminMiddleware())
	{
		orgAdmin.GET("/stats", organizationHandler.GetOrganizationStats)
	}
}

// corsMiddleware adds CORS headers
func corsMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
}

// startCleanupService starts background cleanup tasks
func startCleanupService(cfg *config.Config, messageService *services.MessageService, adminService *services.AdminService) {
	if !cfg.Cleanup.Enabled {
		log.Println("Cleanup service is disabled")
		return
	}

	log.Printf("Starting cleanup service with interval: %v", cfg.Cleanup.RunInterval)

	ticker := time.NewTicker(cfg.Cleanup.RunInterval)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Running cleanup tasks...")

		// Cleanup expired messages
		if deletedMessages, err := messageService.CleanupExpiredMessages(); err != nil {
			log.Printf("Failed to cleanup expired messages: %v", err)
		} else if deletedMessages > 0 {
			log.Printf("Cleaned up %d expired messages", deletedMessages)
		}

		// Cleanup expired blocks
		if unblockedUsers, err := adminService.CleanupExpiredBlocks(); err != nil {
			log.Printf("Failed to cleanup expired blocks: %v", err)
		} else if unblockedUsers > 0 {
			log.Printf("Unblocked %d users with expired blocks", unblockedUsers)
		}

		log.Println("Cleanup tasks completed")
	}
}

// logServerInfo logs server startup information
func logServerInfo(cfg *config.Config) {
	log.Println("=====================================")
	log.Println("       YuMSG Server Starting")
	log.Println("=====================================")
	log.Printf("Version: %s", cfg.App.Version)
	log.Printf("Environment: %s", cfg.App.Environment)
	log.Printf("Server Address: %s", cfg.GetServerAddress())
	log.Printf("Organization: %s (%s)", cfg.App.Organization.Name, cfg.App.Organization.Domain)
	log.Printf("Database: %s:%d/%s", cfg.Database.Host, cfg.Database.Port, cfg.Database.DBName)
	log.Printf("JWT Issuer: %s", cfg.JWT.Issuer)
	log.Printf("Cleanup Enabled: %v", cfg.Cleanup.Enabled)
	if cfg.Cleanup.Enabled {
		log.Printf("Cleanup Interval: %v", cfg.Cleanup.RunInterval)
	}
	log.Println("=====================================")
}
