package services

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"yumsg-server/internal/config"
	"yumsg-server/internal/models"
)

var (
	ErrDefaultOrganizationNotFound = errors.New("default organization not found")
)

// OrganizationService handles organization-related operations
type OrganizationService struct {
	db     *gorm.DB
	config *config.Config
}

// NewOrganizationService creates a new organization service
func NewOrganizationService(db *gorm.DB, cfg *config.Config) *OrganizationService {
	return &OrganizationService{
		db:     db,
		config: cfg,
	}
}

// GetOrganizationInfo returns organization information with supported algorithms
func (s *OrganizationService) GetOrganizationInfo() (*models.OrganizationInfo, error) {
	// Simply return organization info from config
	// No need to query database - 1 server = 1 organization

	orgInfo := &models.OrganizationInfo{
		ID:     s.config.App.Organization.ID,
		Name:   s.config.App.Organization.Name,
		Domain: s.config.App.Organization.Domain,
		ServerPolicies: models.ServerPolicies{
			MaxFileSize:                s.config.App.ServerPolicies.MaxFileSize,
			MessageRetentionDays:       s.config.App.ServerPolicies.MessageRetentionDays,
			MaxConcurrentConnections:   s.config.App.ServerPolicies.MaxConcurrentConnections,
			RateLimitMessagesPerMinute: s.config.App.ServerPolicies.RateLimitMessagesPerMinute,
		},
	}

	// Parse supported algorithms from config
	if s.config.App.SupportedAlgorithms != nil {
		orgInfo.SupportedAlgorithms = s.parseAlgorithmsFromMap(s.config.App.SupportedAlgorithms)
	}

	return orgInfo, nil
}

// GetOrganizationStats returns statistics for an organization
func (s *OrganizationService) GetOrganizationStats(orgID uuid.UUID) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Count users in organization (all users belong to this server's organization)
	var userCount int64
	if err := s.db.Model(&models.User{}).Count(&userCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count users: %w", err)
	}
	stats["total_users"] = userCount

	// Count active users
	var activeUserCount int64
	if err := s.db.Model(&models.User{}).
		Where("status IN (?)", []string{"online", "offline_connected"}).
		Count(&activeUserCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count active users: %w", err)
	}
	stats["active_users"] = activeUserCount

	// Count total chats in organization (all chats belong to this organization)
	var chatCount int64
	if err := s.db.Model(&models.ChatMetadata{}).Count(&chatCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count chats: %w", err)
	}
	stats["total_chats"] = chatCount

	return stats, nil
}

// parseAlgorithmsFromMap parses algorithms from JSON map
func (s *OrganizationService) parseAlgorithmsFromMap(algos map[string]interface{}) models.SupportedAlgorithms {
	var supportedAlgorithms models.SupportedAlgorithms

	// Parse asymmetric algorithms
	if asymmetric, ok := algos["asymmetric"].([]interface{}); ok {
		for _, algo := range asymmetric {
			if algoMap, ok := algo.(map[string]interface{}); ok {
				algorithm := models.Algorithm{}

				if name, ok := algoMap["name"].(string); ok {
					algorithm.Name = name
				}
				if desc, ok := algoMap["description"].(string); ok {
					algorithm.Description = desc
				}
				if keySize, ok := algoMap["key_size"].(float64); ok {
					algorithm.KeySize = int(keySize)
				}
				if recommended, ok := algoMap["recommended"].(bool); ok {
					algorithm.Recommended = recommended
				}

				supportedAlgorithms.Asymmetric = append(supportedAlgorithms.Asymmetric, algorithm)
			}
		}
	}

	// Parse symmetric algorithms
	if symmetric, ok := algos["symmetric"].([]interface{}); ok {
		for _, algo := range symmetric {
			if algoMap, ok := algo.(map[string]interface{}); ok {
				algorithm := models.Algorithm{}

				if name, ok := algoMap["name"].(string); ok {
					algorithm.Name = name
				}
				if desc, ok := algoMap["description"].(string); ok {
					algorithm.Description = desc
				}
				if keySize, ok := algoMap["key_size"].(float64); ok {
					algorithm.KeySize = int(keySize)
				}
				if recommended, ok := algoMap["recommended"].(bool); ok {
					algorithm.Recommended = recommended
				}

				supportedAlgorithms.Symmetric = append(supportedAlgorithms.Symmetric, algorithm)
			}
		}
	}

	// Parse signature algorithms
	if signature, ok := algos["signature"].([]interface{}); ok {
		for _, algo := range signature {
			if algoMap, ok := algo.(map[string]interface{}); ok {
				algorithm := models.Algorithm{}

				if name, ok := algoMap["name"].(string); ok {
					algorithm.Name = name
				}
				if desc, ok := algoMap["description"].(string); ok {
					algorithm.Description = desc
				}
				if keySize, ok := algoMap["key_size"].(float64); ok {
					algorithm.KeySize = int(keySize)
				}
				if recommended, ok := algoMap["recommended"].(bool); ok {
					algorithm.Recommended = recommended
				}

				supportedAlgorithms.Signature = append(supportedAlgorithms.Signature, algorithm)
			}
		}
	}

	return supportedAlgorithms
}
