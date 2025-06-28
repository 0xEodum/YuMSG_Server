package auth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"yumsg-server/internal/config"
	"yumsg-server/internal/models"
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("expired token")
	ErrTokenNotFound      = errors.New("token not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserBlocked        = errors.New("user is blocked")
)

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey   []byte
	expiryTime  time.Duration
	refreshTime time.Duration
	issuer      string
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(cfg *config.Config) *JWTManager {
	return &JWTManager{
		secretKey:   []byte(cfg.JWT.SecretKey),
		expiryTime:  cfg.JWT.ExpiryTime,
		refreshTime: cfg.JWT.RefreshTime,
		issuer:      cfg.JWT.Issuer,
	}
}

// GenerateToken generates a new JWT token for a user
func (j *JWTManager) GenerateToken(user *models.User) (string, time.Time, error) {
	expiresAt := time.Now().Add(j.expiryTime)

	claims := &JWTClaims{
		UserID:   user.ID.String(),
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    j.issuer,
			Subject:   user.ID.String(),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secretKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ExtractTokenFromHeader extracts JWT token from Authorization header
func (j *JWTManager) ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", ErrTokenNotFound
	}

	// Check if header starts with "Bearer "
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return "", ErrTokenNotFound
	}

	// Extract the token part
	token := strings.TrimPrefix(authHeader, bearerPrefix)
	if token == "" {
		return "", ErrTokenNotFound
	}

	return token, nil
}

// PasswordManager handles password hashing and verification
type PasswordManager struct {
	cost int
}

// NewPasswordManager creates a new password manager
func NewPasswordManager() *PasswordManager {
	return &PasswordManager{
		cost: bcrypt.DefaultCost,
	}
}

// HashPassword hashes a plain text password
func (p *PasswordManager) HashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedBytes), nil
}

// VerifyPassword verifies a password against its hash
func (p *PasswordManager) VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("failed to verify password: %w", err)
	}
	return nil
}

// AuthService combines JWT and password management
type AuthService struct {
	jwtManager      *JWTManager
	passwordManager *PasswordManager
}

// NewAuthService creates a new authentication service
func NewAuthService(cfg *config.Config) *AuthService {
	return &AuthService{
		jwtManager:      NewJWTManager(cfg),
		passwordManager: NewPasswordManager(),
	}
}

// GenerateToken generates a JWT token for a user
func (a *AuthService) GenerateToken(user *models.User) (string, time.Time, error) {
	return a.jwtManager.GenerateToken(user)
}

// ValidateToken validates a JWT token and returns claims
func (a *AuthService) ValidateToken(tokenString string) (*JWTClaims, error) {
	return a.jwtManager.ValidateToken(tokenString)
}

// HashPassword hashes a password
func (a *AuthService) HashPassword(password string) (string, error) {
	return a.passwordManager.HashPassword(password)
}

// VerifyPassword verifies a password
func (a *AuthService) VerifyPassword(hashedPassword, password string) error {
	return a.passwordManager.VerifyPassword(hashedPassword, password)
}

// ExtractTokenFromContext extracts JWT token from Gin context
func (a *AuthService) ExtractTokenFromContext(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	return a.jwtManager.ExtractTokenFromHeader(authHeader)
}

// AuthMiddleware creates a Gin middleware for JWT authentication
func (a *AuthService) AuthMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token, err := a.ExtractTokenFromContext(c)
		if err != nil {
			c.JSON(401, models.ErrorResponse{
				Success:          false,
				Error:            "authentication_required",
				ErrorCode:        "MISSING_TOKEN",
				ErrorDescription: "Authorization token is required",
			})
			c.Abort()
			return
		}

		claims, err := a.ValidateToken(token)
		if err != nil {
			var errorCode string
			var description string

			switch {
			case errors.Is(err, ErrExpiredToken):
				errorCode = "TOKEN_EXPIRED"
				description = "Authorization token has expired"
			case errors.Is(err, ErrInvalidToken):
				errorCode = "INVALID_TOKEN"
				description = "Authorization token is invalid"
			default:
				errorCode = "TOKEN_ERROR"
				description = "Token validation failed"
			}

			c.JSON(401, models.ErrorResponse{
				Success:          false,
				Error:            "authentication_failed",
				ErrorCode:        errorCode,
				ErrorDescription: description,
			})
			c.Abort()
			return
		}

		// Store claims in context for use in handlers
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("claims", claims)

		c.Next()
	})
}

// OptionalAuthMiddleware creates a middleware that doesn't require auth but extracts it if present
func (a *AuthService) OptionalAuthMiddleware() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		token, err := a.ExtractTokenFromContext(c)
		if err != nil {
			// No token provided, continue without auth
			c.Next()
			return
		}

		claims, err := a.ValidateToken(token)
		if err != nil {
			// Invalid token, continue without auth
			c.Next()
			return
		}

		// Store claims in context if valid
		c.Set("user_id", claims.UserID)
		c.Set("username", claims.Username)
		c.Set("claims", claims)

		c.Next()
	})
}

// GetUserIDFromContext extracts user ID from Gin context
func GetUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	userIDStr, exists := c.Get("user_id")
	if !exists {
		return uuid.Nil, errors.New("user ID not found in context")
	}

	userIDString, ok := userIDStr.(string)
	if !ok {
		return uuid.Nil, errors.New("invalid user ID format in context")
	}

	userID, err := uuid.Parse(userIDString)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to parse user ID: %w", err)
	}

	return userID, nil
}

// GetUsernameFromContext extracts username from Gin context
func GetUsernameFromContext(c *gin.Context) (string, error) {
	username, exists := c.Get("username")
	if !exists {
		return "", errors.New("username not found in context")
	}

	usernameStr, ok := username.(string)
	if !ok {
		return "", errors.New("invalid username format in context")
	}

	return usernameStr, nil
}
