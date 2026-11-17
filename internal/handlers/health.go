// Package handlers contains thin HTTP handlers. Handlers parse requests,
// call services, and render/respond. Business rules live in the service layer.
package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HealthResponse is the JSON body returned by the health endpoint.
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// Health handles GET /health. It reports that the process is up and serving.
// It intentionally performs no external dependency checks in this phase; those
// are added when database connectivity is introduced.
func Health(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:  "ok",
		Service: "core",
	})
}
