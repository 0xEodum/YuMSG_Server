package api

import (
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
			"name": orgInfo.Name,
		},
		"message": "Organization statistics endpoint - implement detailed stats as needed",
	}

	c.JSON(http.StatusOK, response)
}
