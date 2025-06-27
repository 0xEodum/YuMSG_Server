package config

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	App      AppConfig      `mapstructure:"app"`
	Cleanup  CleanupConfig  `mapstructure:"cleanup"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	DBName   string `mapstructure:"dbname"`
	SSLMode  string `mapstructure:"sslmode"`
}

type JWTConfig struct {
	SecretKey   string        `mapstructure:"secret_key"`
	ExpiryTime  time.Duration `mapstructure:"expiry_time"`
	RefreshTime time.Duration `mapstructure:"refresh_time"`
	Issuer      string        `mapstructure:"issuer"`
}

type AppConfig struct {
	Version             string                 `mapstructure:"version"`
	Environment         string                 `mapstructure:"environment"`
	LogLevel            string                 `mapstructure:"log_level"`
	Organization        OrganizationConfig     `mapstructure:"organization"`
	SupportedAlgorithms map[string]interface{} `mapstructure:"supported_algorithms"`
	ServerPolicies      ServerPoliciesConfig   `mapstructure:"server_policies"`
	WebSocket           WebSocketConfig        `mapstructure:"websocket"`
}

type OrganizationConfig struct {
	ID     string `mapstructure:"id"`
	Name   string `mapstructure:"name"`
	Domain string `mapstructure:"domain"`
}

type ServerPoliciesConfig struct {
	MaxFileSize                int `mapstructure:"max_file_size"`
	MessageRetentionDays       int `mapstructure:"message_retention_days"`
	MaxConcurrentConnections   int `mapstructure:"max_concurrent_connections"`
	RateLimitMessagesPerMinute int `mapstructure:"rate_limit_messages_per_minute"`
}

type WebSocketConfig struct {
	HeartbeatInterval time.Duration `mapstructure:"heartbeat_interval"`
	ConnectionTimeout time.Duration `mapstructure:"connection_timeout"`
	MaxMessageSize    int64         `mapstructure:"max_message_size"`
}

type CleanupConfig struct {
	Enabled               bool          `mapstructure:"enabled"`
	RunInterval           time.Duration `mapstructure:"run_interval"`
	ExpiredMessagesAge    time.Duration `mapstructure:"expired_messages_age"`
	InactiveConnectionAge time.Duration `mapstructure:"inactive_connection_age"`
	AuditLogRetention     time.Duration `mapstructure:"audit_log_retention"`
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")

	// Set default values
	setDefaults()

	// Enable reading from environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("YUMSG")

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		// Config file not found, use defaults and env vars
	}

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Override with environment variables
	overrideWithEnv(&config)

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &config, nil
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "30s")
	viper.SetDefault("server.idle_timeout", "120s")

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "yumsg")
	viper.SetDefault("database.password", "password")
	viper.SetDefault("database.dbname", "yumsg")
	viper.SetDefault("database.sslmode", "disable")

	// JWT defaults
	viper.SetDefault("jwt.secret_key", "your-super-secret-jwt-key-change-this-in-production")
	viper.SetDefault("jwt.expiry_time", "24h")
	viper.SetDefault("jwt.refresh_time", "72h")
	viper.SetDefault("jwt.issuer", "yumsg-server")

	// App defaults
	viper.SetDefault("app.version", "1.0.0")
	viper.SetDefault("app.environment", "development")
	viper.SetDefault("app.log_level", "info")

	// Organization defaults
	viper.SetDefault("app.organization.id", "00000000-0000-0000-0000-000000000000")
	viper.SetDefault("app.organization.name", "Default Organization")
	viper.SetDefault("app.organization.domain", "localhost")

	// Server policies defaults
	viper.SetDefault("app.server_policies.max_file_size", 52428800) // 50MB
	viper.SetDefault("app.server_policies.message_retention_days", 7)
	viper.SetDefault("app.server_policies.max_concurrent_connections", 1000)
	viper.SetDefault("app.server_policies.rate_limit_messages_per_minute", 60)

	// WebSocket defaults
	viper.SetDefault("app.websocket.heartbeat_interval", "10s")
	viper.SetDefault("app.websocket.connection_timeout", "60s")
	viper.SetDefault("app.websocket.max_message_size", 1024*1024) // 1MB

	// Cleanup defaults
	viper.SetDefault("cleanup.enabled", true)
	viper.SetDefault("cleanup.run_interval", "1h")
	viper.SetDefault("cleanup.expired_messages_age", "168h")    // 7 days
	viper.SetDefault("cleanup.inactive_connection_age", "300s") // 5 minutes
	viper.SetDefault("cleanup.audit_log_retention", "720h")     // 30 days

	// Default supported algorithms
	defaultAlgorithms := map[string]interface{}{
		"asymmetric": []map[string]interface{}{
			{
				"name":        "NTRU",
				"description": "Решетчатый алгоритм",
				"key_size":    1024,
				"recommended": true,
			},
			{
				"name":        "BIKE",
				"description": "Код-основанный алгоритм",
				"key_size":    2048,
				"recommended": false,
			},
		},
		"symmetric": []map[string]interface{}{
			{
				"name":        "AES-256",
				"description": "Стандарт шифрования",
				"key_size":    256,
				"recommended": true,
			},
			{
				"name":        "ChaCha20",
				"description": "Потоковый шифр",
				"key_size":    256,
				"recommended": false,
			},
		},
		"signature": []map[string]interface{}{
			{
				"name":        "Falcon",
				"description": "Решетчатая подпись",
				"key_size":    1024,
				"recommended": true,
			},
			{
				"name":        "Dilithium",
				"description": "Модульная решетчатая подпись",
				"key_size":    2048,
				"recommended": false,
			},
		},
	}

	viper.SetDefault("app.supported_algorithms", defaultAlgorithms)
}

func overrideWithEnv(config *Config) {
	// Override database config with environment variables
	if dbHost := os.Getenv("YUMSG_DB_HOST"); dbHost != "" {
		config.Database.Host = dbHost
	}
	if dbPort := os.Getenv("YUMSG_DB_PORT"); dbPort != "" {
		viper.Set("database.port", dbPort)
	}
	if dbUser := os.Getenv("YUMSG_DB_USER"); dbUser != "" {
		config.Database.User = dbUser
	}
	if dbPassword := os.Getenv("YUMSG_DB_PASSWORD"); dbPassword != "" {
		config.Database.Password = dbPassword
	}
	if dbName := os.Getenv("YUMSG_DB_NAME"); dbName != "" {
		config.Database.DBName = dbName
	}

	// Override JWT secret key
	if jwtSecret := os.Getenv("YUMSG_JWT_SECRET"); jwtSecret != "" {
		config.JWT.SecretKey = jwtSecret
	}

	// Override server config
	if serverHost := os.Getenv("YUMSG_SERVER_HOST"); serverHost != "" {
		config.Server.Host = serverHost
	}
	if serverPort := os.Getenv("YUMSG_SERVER_PORT"); serverPort != "" {
		viper.Set("server.port", serverPort)
	}
}

func validateConfig(config *Config) error {
	if config.JWT.SecretKey == "" {
		return fmt.Errorf("JWT secret key cannot be empty")
	}

	if config.JWT.SecretKey == "your-super-secret-jwt-key-change-this-in-production" {
		if config.App.Environment == "production" {
			return fmt.Errorf("default JWT secret key cannot be used in production")
		}
	}

	if config.Database.Host == "" {
		return fmt.Errorf("database host cannot be empty")
	}

	if config.Database.User == "" {
		return fmt.Errorf("database user cannot be empty")
	}

	if config.Database.DBName == "" {
		return fmt.Errorf("database name cannot be empty")
	}

	if config.App.Organization.Name == "" {
		return fmt.Errorf("organization name cannot be empty")
	}

	return nil
}

// GetDSN returns the database connection string
func (c *Config) GetDSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.DBName,
		c.Database.SSLMode,
	)
}

// GetServerAddress returns the server address
func (c *Config) GetServerAddress() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
