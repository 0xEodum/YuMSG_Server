package database

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"yumsg-server/internal/config"
	"yumsg-server/internal/models"
)

type Database struct {
	DB *gorm.DB
}

// NewDatabase creates a new database connection
func NewDatabase(cfg *config.Config) (*Database, error) {
	// Configure GORM logger based on environment
	var gormLogger logger.Interface
	if cfg.App.Environment == "development" {
		gormLogger = logger.Default.LogMode(logger.Info)
	} else {
		gormLogger = logger.Default.LogMode(logger.Error)
	}

	// Open database connection
	db, err := gorm.Open(postgres.Open(cfg.GetDSN()), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Set connection pool settings
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Successfully connected to database")

	return &Database{DB: db}, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// AutoMigrate runs database migrations
func (d *Database) AutoMigrate() error {
	log.Println("Running database migrations...")

	err := d.DB.AutoMigrate(
		&models.User{},
		&models.ActiveConnection{},
		&models.ChatMetadata{},
		&models.PendingMessage{},
		&models.AuditLog{},
		&models.BlockedUser{},
	)
	if err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// Create indexes manually if needed
	if err := d.createIndexes(); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// createIndexes creates additional database indexes
func (d *Database) createIndexes() error {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)",
		"CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(LOWER(username))",
		"CREATE INDEX IF NOT EXISTS idx_users_display_name_gin ON users USING gin(to_tsvector('english', display_name))",
		"CREATE INDEX IF NOT EXISTS idx_active_connections_user ON active_connections(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_active_connections_last_heartbeat ON active_connections(last_heartbeat)",
		"CREATE INDEX IF NOT EXISTS idx_chat_metadata_users ON chat_metadata(user1_id, user2_id)",
		"CREATE INDEX IF NOT EXISTS idx_chat_metadata_chat_uuid ON chat_metadata(chat_uuid)",
		"CREATE INDEX IF NOT EXISTS idx_pending_messages_recipient ON pending_messages(recipient_id)",
		"CREATE INDEX IF NOT EXISTS idx_pending_messages_expires ON pending_messages(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_pending_messages_delivered ON pending_messages(delivered)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_blocked_users_user_id ON blocked_users(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked_until ON blocked_users(blocked_until)",
	}

	for _, index := range indexes {
		if err := d.DB.Exec(index).Error; err != nil {
			log.Printf("Warning: Failed to create index: %s - %v", index, err)
		}
	}

	return nil
}

// Health checks database connectivity
func (d *Database) Health() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

// GetStats returns database statistics
func (d *Database) GetStats() (map[string]interface{}, error) {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	stats := sqlDB.Stats()

	return map[string]interface{}{
		"open_connections":     stats.OpenConnections,
		"idle_connections":     stats.Idle,
		"in_use_connections":   stats.InUse,
		"wait_count":           stats.WaitCount,
		"wait_duration":        stats.WaitDuration.String(),
		"max_idle_closed":      stats.MaxIdleClosed,
		"max_idle_time_closed": stats.MaxIdleTimeClosed,
		"max_lifetime_closed":  stats.MaxLifetimeClosed,
	}, nil
}

// Transaction executes a function within a database transaction
func (d *Database) Transaction(fn func(*gorm.DB) error) error {
	return d.DB.Transaction(fn)
}

// BeginTransaction starts a new database transaction
func (d *Database) BeginTransaction() *gorm.DB {
	return d.DB.Begin()
}
