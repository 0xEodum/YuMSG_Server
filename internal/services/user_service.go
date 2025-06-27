package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"yumsg-server/internal/auth"
	"yumsg-server/internal/models"
)

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrInvalidUserData      = errors.New("invalid user data")
	ErrOrganizationNotFound = errors.New("organization not found")
)

// UserService handles user-related operations
type UserService struct {
	db          *gorm.DB
	authService *auth.AuthService
	orgService  *OrganizationService
}

// NewUserService creates a new user service
func NewUserService(db *gorm.DB, authService *auth.AuthService, orgService *OrganizationService) *UserService {
	return &UserService{
		db:          db,
		authService: authService,
		orgService:  orgService,
	}
}

// CreateUser creates a new user
func (s *UserService) CreateUser(req *models.RegisterRequest) (*models.User, error) {
	// Validate input
	if err := s.validateRegisterRequest(req); err != nil {
		return nil, err
	}

	// Check if organization domain matches our server's organization
	org, err := s.orgService.GetOrganizationByDomain(req.OrganizationDomain)
	if err != nil {
		if errors.Is(err, ErrOrganizationNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to get organization: %w", err)
	}

	// Check if user already exists
	var existingUser models.User
	if err := s.db.Where("username = ?", strings.ToLower(req.Username)).First(&existingUser).Error; err == nil {
		return nil, ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := s.authService.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		OrganizationID: org.ID,
		Username:       strings.ToLower(req.Username),
		Email:          req.Email,
		PasswordHash:   hashedPassword,
		DisplayName:    req.DisplayName,
		Status:         models.StatusOfflineDisconnected,
	}

	if err := s.db.Create(user).Error; err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Load organization relationship
	if err := s.db.Preload("Organization").First(user, user.ID).Error; err != nil {
		return nil, fmt.Errorf("failed to load user organization: %w", err)
	}

	return user, nil
}

// AuthenticateUser authenticates a user and returns a JWT token
func (s *UserService) AuthenticateUser(req *models.LoginRequest) (*models.User, string, time.Time, error) {
	// Find user by username
	var user models.User
	if err := s.db.Preload("Organization").Where("username = ?", strings.ToLower(req.Username)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", time.Time{}, auth.ErrInvalidCredentials
		}
		return nil, "", time.Time{}, fmt.Errorf("failed to find user: %w", err)
	}

	// Check if user is blocked
	if user.IsBlocked {
		return nil, "", time.Time{}, auth.ErrUserBlocked
	}

	// Verify password
	if err := s.authService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, "", time.Time{}, err
	}

	// Generate JWT token
	token, expiresAt, err := s.authService.GenerateToken(&user)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("failed to generate token: %w", err)
	}

	// Update last seen
	now := time.Now()
	user.LastSeen = &now
	if err := s.db.Save(&user).Error; err != nil {
		// Log error but don't fail the authentication
		fmt.Printf("Warning: failed to update last seen: %v\n", err)
	}

	return &user, token, expiresAt, nil
}

// GetUserByID retrieves a user by ID
func (s *UserService) GetUserByID(userID uuid.UUID) (*models.User, error) {
	var user models.User
	if err := s.db.Preload("Organization").First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	var user models.User
	if err := s.db.Preload("Organization").Where("username = ?", strings.ToLower(username)).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// UpdateUserProfile updates user profile information
func (s *UserService) UpdateUserProfile(userID uuid.UUID, req *models.UpdateProfileRequest) (*models.User, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Update fields
	if req.DisplayName != "" {
		user.DisplayName = req.DisplayName
	}
	if req.Email != "" {
		user.Email = req.Email
	}

	// Save changes
	if err := s.db.Save(&user).Error; err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	// Reload with organization
	if err := s.db.Preload("Organization").First(&user, user.ID).Error; err != nil {
		return nil, fmt.Errorf("failed to reload user: %w", err)
	}

	return &user, nil
}

// SearchUsers searches for users by query (username or display name)
func (s *UserService) SearchUsers(query string, limit, offset int, currentUserID uuid.UUID) ([]models.User, int, error) {
	if len(query) < 2 {
		return nil, 0, errors.New("query must be at least 2 characters")
	}

	var users []models.User
	var total int64

	searchQuery := "%" + strings.ToLower(query) + "%"

	// Since 1 server = 1 organization, no need to filter by organization_id
	baseQuery := s.db.Where("id != ? AND is_blocked = false", currentUserID).
		Where("(LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?)", searchQuery, searchQuery)

	// Count total results
	if err := baseQuery.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get paginated results
	if err := baseQuery.
		Order("display_name ASC").
		Limit(limit).
		Offset(offset).
		Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to search users: %w", err)
	}

	return users, int(total), nil
}

// GetUserStatus retrieves detailed status information for a user
func (s *UserService) GetUserStatus(userID uuid.UUID) (*models.User, *models.ActiveConnection, error) {
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, ErrUserNotFound
		}
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Get active connection if exists
	var connection models.ActiveConnection
	err := s.db.Where("user_id = ?", userID).
		Order("last_heartbeat DESC").
		First(&connection).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, fmt.Errorf("failed to get connection: %w", err)
	}

	if errors.Is(err, gorm.ErrRecordNotFound) {
		return &user, nil, nil
	}

	return &user, &connection, nil
}

// UpdateUserStatus updates user online status
func (s *UserService) UpdateUserStatus(userID uuid.UUID, status models.UserStatus) error {
	now := time.Now()
	updates := map[string]interface{}{
		"status":    status,
		"last_seen": now,
	}

	if err := s.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	return nil
}

// BlockUser blocks a user
func (s *UserService) BlockUser(userID, adminID uuid.UUID, req *models.BlockUserRequest) (*models.BlockedUser, error) {
	// Check if user exists
	var user models.User
	if err := s.db.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Block the user
	if err := s.db.Model(&user).Update("is_blocked", true).Error; err != nil {
		return nil, fmt.Errorf("failed to block user: %w", err)
	}

	// Create blocked user record
	var blockedUntil *time.Time
	if req.DurationHours > 0 {
		until := time.Now().Add(time.Duration(req.DurationHours) * time.Hour)
		blockedUntil = &until
	}

	blockedUser := &models.BlockedUser{
		UserID:       userID,
		BlockedBy:    adminID,
		Reason:       req.Reason,
		Description:  req.Description,
		BlockedUntil: blockedUntil,
	}

	if err := s.db.Create(blockedUser).Error; err != nil {
		return nil, fmt.Errorf("failed to create blocked user record: %w", err)
	}

	// Load relationships
	if err := s.db.Preload("User").Preload("AdminUser").First(blockedUser, blockedUser.ID).Error; err != nil {
		return nil, fmt.Errorf("failed to load blocked user: %w", err)
	}

	return blockedUser, nil
}

// GetAllUsers retrieves all users with pagination (admin function)
func (s *UserService) GetAllUsers(limit, offset int, status string, sortBy string) ([]models.User, int, error) {
	var users []models.User
	var total int64

	query := s.db.Preload("Organization").Where("1 = 1")

	// Apply status filter
	if status != "all" && status != "" {
		query = query.Where("status = ?", status)
	}

	// Count total
	if err := query.Model(&models.User{}).Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Apply sorting
	switch sortBy {
	case "username":
		query = query.Order("username ASC")
	case "status":
		query = query.Order("status ASC, display_name ASC")
	case "last_seen":
		query = query.Order("last_seen DESC")
	default:
		query = query.Order("created_at DESC")
	}

	// Get paginated results
	if err := query.Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get users: %w", err)
	}

	return users, int(total), nil
}

// validateRegisterRequest validates user registration data
func (s *UserService) validateRegisterRequest(req *models.RegisterRequest) error {
	if req.Username == "" {
		return errors.New("username is required")
	}

	if len(req.Password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	if req.DisplayName == "" {
		return errors.New("display name is required")
	}

	if req.Email == "" {
		return errors.New("email is required")
	}

	if req.OrganizationDomain == "" {
		return errors.New("organization domain is required")
	}

	// Basic email validation
	if !strings.Contains(req.Username, "@") || !strings.Contains(req.Username, ".") {
		return errors.New("username must be a valid email address")
	}

	return nil
}

// HasActiveChat checks if two users have an active chat
func (s *UserService) HasActiveChat(user1ID, user2ID uuid.UUID) (bool, error) {
	var count int64
	err := s.db.Model(&models.ChatMetadata{}).
		Where("(user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)",
			user1ID, user2ID, user2ID, user1ID).
		Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("failed to check active chat: %w", err)
	}

	return count > 0, nil
}
