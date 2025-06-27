package services

import (
	"encoding/json"
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

// GetOrganizationByDomain returns organization by domain (from config)
func (s *OrganizationService) GetOrganizationByDomain(domain string) (*models.Organization, error) {
	// Check if the requested domain matches our configured domain
	if domain != s.config.App.Organization.Domain {
		return nil, ErrOrganizationNotFound
	}

	// Return organization from config
	orgUUID, err := uuid.Parse(s.config.App.Organization.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid organization ID in config: %w", err)
	}

	// Convert supported algorithms to JSON
	var supportedAlgorithmsJSON []byte
	if s.config.App.SupportedAlgorithms != nil {
		supportedAlgorithmsJSON, err = json.Marshal(s.config.App.SupportedAlgorithms)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal supported algorithms: %w", err)
		}
	}

	org := &models.Organization{
		ID:                  orgUUID,
		Name:                s.config.App.Organization.Name,
		Domain:              s.config.App.Organization.Domain,
		SupportedAlgorithms: supportedAlgorithmsJSON,
	}

	return org, nil
}

// GetOrganizationByID returns organization by ID (from config)
func (s *OrganizationService) GetOrganizationByID(id uuid.UUID) (*models.Organization, error) {
	// Check if the requested ID matches our configured ID
	configOrgID, err := uuid.Parse(s.config.App.Organization.ID)
	if err != nil {
		return nil, fmt.Errorf("invalid organization ID in config: %w", err)
	}

	if id != configOrgID {
		return nil, ErrOrganizationNotFound
	}

	// Return organization from config
	return s.GetOrganizationByDomain(s.config.App.Organization.Domain)
}

// GetAllOrganizations returns all organizations (admin function)
func (s *OrganizationService) GetAllOrganizations() ([]models.Organization, error) {
	var organizations []models.Organization
	if err := s.db.Find(&organizations).Error; err != nil {
		return nil, fmt.Errorf("failed to get organizations: %w", err)
	}

	return organizations, nil
}

// CreateOrganization creates a new organization
func (s *OrganizationService) CreateOrganization(name, domain string, supportedAlgorithms json.RawMessage) (*models.Organization, error) {
	// Check if organization with domain already exists
	var existingOrg models.Organization
	if err := s.db.Where("domain = ?", domain).First(&existingOrg).Error; err == nil {
		return nil, errors.New("organization with this domain already exists")
	}

	org := &models.Organization{
		Name:                name,
		Domain:              domain,
		SupportedAlgorithms: supportedAlgorithms,
	}

	if err := s.db.Create(org).Error; err != nil {
		return nil, fmt.Errorf("failed to create organization: %w", err)
	}

	return org, nil
}

// UpdateOrganization updates organization information
func (s *OrganizationService) UpdateOrganization(id uuid.UUID, name string, supportedAlgorithms json.RawMessage) (*models.Organization, error) {
	var org models.Organization
	if err := s.db.First(&org, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOrganizationNotFound
		}
		return nil, fmt.Errorf("failed to find organization: %w", err)
	}

	// Update fields
	if name != "" {
		org.Name = name
	}
	if supportedAlgorithms != nil {
		org.SupportedAlgorithms = supportedAlgorithms
	}

	if err := s.db.Save(&org).Error; err != nil {
		return nil, fmt.Errorf("failed to update organization: %w", err)
	}

	return &org, nil
}

// helper function to convert map to JSON bytes
func (s *OrganizationService) mapToJSONBytes(data map[string]interface{}) (json.RawMessage, error) {
	if data == nil {
		return nil, nil
	}
	return json.Marshal(data)
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

// ValidateOrganizationDomain validates if a domain is allowed for organization
func (s *OrganizationService) ValidateOrganizationDomain(domain string) error {
	if domain == "" {
		return errors.New("domain cannot be empty")
	}

	// Check if domain already exists
	var count int64
	if err := s.db.Model(&models.Organization{}).Where("domain = ?", domain).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check domain: %w", err)
	}

	if count > 0 {
		return errors.New("domain already exists")
	}

	return nil
}
