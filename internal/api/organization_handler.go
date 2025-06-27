package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"yumsg-server/internal/models"
	"yumsg-server/internal/services"
)

// OrganizationHandler handles organization-related HTTP requests
type OrganizationHandler struct {
	organizationService *services.OrganizationService
}

// NewOrganizationHandler creates a new organization handler
func NewOrganizationHandler(organizationService *services.OrganizationService) *OrganizationHandler {
	return &OrganizationHandler{
		organizationService: organizationService,
	}
}

// GetOrganizationInfo returns public information about the organization
// GET /api/organization/info
func (h *OrganizationHandler) GetOrganizationInfo(c *gin.Context) {
	orgInfo, err := h.organizationService.GetOrganizationInfo()
	if err != nil {
		if errors.Is(err, services.ErrDefaultOrganizationNotFound) {
			c.JSON(http.StatusNotFound, models.ErrorResponse{
				Success:          false,
				Error:            "organization_not_found",
				ErrorCode:        "ORGANIZATION_NOT_FOUND",
				ErrorDescription: "Default organization not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve organization information",
		})
		return
	}

	response := models.OrganizationInfoResponse{
		Success:      true,
		Organization: *orgInfo,
	}

	c.JSON(http.StatusOK, response)
}

// GetOrganizationStats returns organization statistics (protected endpoint)
// GET /api/organization/stats
func (h *OrganizationHandler) GetOrganizationStats(c *gin.Context) {
	// This would typically be protected and require admin privileges
	// For now, we'll implement it as a basic endpoint

	orgInfo, err := h.organizationService.GetOrganizationInfo()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve organization information",
		})
		return
	}

	// Get organization by ID to fetch stats
	// This is a simplified implementation
	response := map[string]interface{}{
		"success": true,
		"organization": map[string]interface{}{
			"id":     orgInfo.ID,
			"name":   orgInfo.Name,
			"domain": orgInfo.Domain,
		},
		"message": "Organization statistics endpoint - implement detailed stats as needed",
	}

	c.JSON(http.StatusOK, response)
}

// CreateOrganization creates a new organization (admin only)
// POST /api/organizations
func (h *OrganizationHandler) CreateOrganization(c *gin.Context) {
	var req struct {
		Name                string      `json:"name" binding:"required"`
		Domain              string      `json:"domain" binding:"required"`
		SupportedAlgorithms interface{} `json:"supported_algorithms"`
	}

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

	// Validate domain
	if err := h.organizationService.ValidateOrganizationDomain(req.Domain); err != nil {
		c.JSON(http.StatusConflict, models.ErrorResponse{
			Success:          false,
			Error:            "domain_invalid",
			ErrorCode:        "DOMAIN_EXISTS",
			ErrorDescription: err.Error(),
		})
		return
	}

	// Convert supported algorithms to JSON
	var supportedAlgorithmsJSON []byte
	if req.SupportedAlgorithms != nil {
		var err error
		supportedAlgorithmsJSON, err = json.Marshal(req.SupportedAlgorithms)
		if err != nil {
			c.JSON(http.StatusBadRequest, models.ErrorResponse{
				Success:          false,
				Error:            "invalid_algorithms",
				ErrorCode:        "INVALID_ALGORITHMS_FORMAT",
				ErrorDescription: "Invalid supported algorithms format",
			})
			return
		}
	}

	// Create organization
	org, err := h.organizationService.CreateOrganization(req.Name, req.Domain, supportedAlgorithmsJSON)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "creation_failed",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to create organization",
		})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Organization created successfully",
		"organization": map[string]interface{}{
			"id":         org.ID.String(),
			"name":       org.Name,
			"domain":     org.Domain,
			"created_at": org.CreatedAt,
		},
	}

	c.JSON(http.StatusCreated, response)
}

// UpdateOrganization updates organization information (admin only)
// PUT /api/organizations/{id}
func (h *OrganizationHandler) UpdateOrganization(c *gin.Context) {
	// This would be an admin-only endpoint
	c.JSON(http.StatusNotImplemented, models.ErrorResponse{
		Success:          false,
		Error:            "not_implemented",
		ErrorCode:        "UPDATE_NOT_IMPLEMENTED",
		ErrorDescription: "Organization update is not implemented yet",
	})
}

// GetAllOrganizations returns all organizations (super admin only)
// GET /api/organizations
func (h *OrganizationHandler) GetAllOrganizations(c *gin.Context) {
	// This would be a super admin endpoint for multi-tenant systems
	orgs, err := h.organizationService.GetAllOrganizations()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Success:          false,
			Error:            "server_error",
			ErrorCode:        "DATABASE_ERROR",
			ErrorDescription: "Failed to retrieve organizations",
		})
		return
	}

	// Convert to response format
	var orgList []map[string]interface{}
	for _, org := range orgs {
		orgList = append(orgList, map[string]interface{}{
			"id":         org.ID.String(),
			"name":       org.Name,
			"domain":     org.Domain,
			"created_at": org.CreatedAt,
		})
	}

	response := map[string]interface{}{
		"success":       true,
		"organizations": orgList,
		"total":         len(orgList),
	}

	c.JSON(http.StatusOK, response)
}
