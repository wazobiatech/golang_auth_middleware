package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	authgo "github.com/wazobiatech/golang_auth_middleware"
)

func main() {
	// Set environment variables for demo (in production, these should be set externally)
	setDemoEnvironment()

	// Initialize Gin router
	r := gin.Default()

	// Health check endpoint (no authentication required)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Public endpoints
	public := r.Group("/public")
	{
		public.GET("/info", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"service": "Demo Auth Service",
				"version": authgo.GetVersion(),
			})
		})
	}

	// JWT protected endpoints
	jwtProtected := r.Group("/user")
	jwtProtected.Use(authgo.GinJWTMiddleware())
	{
		jwtProtected.GET("/profile", getUserProfile)
		jwtProtected.GET("/permissions", getUserPermissions)
	}

	// Project/Platform token protected endpoints
	projectProtected := r.Group("/api/v1")
	projectProtected.Use(authgo.GinProjectMiddleware("demo-service"))
	{
		projectProtected.GET("/projects", getProjects)
		projectProtected.GET("/services", getServices)
		
		// Endpoints that require specific scopes
		scopeProtected := projectProtected.Group("")
		scopeProtected.Use(authgo.GinRequireScope("projects:read", "services:manage"))
		{
			scopeProtected.POST("/services", createService)
			scopeProtected.DELETE("/services/:id", deleteService)
		}
	}

	// Optional authentication endpoints (works with or without auth)
	optional := r.Group("/mixed")
	optional.Use(authgo.GinOptionalJWTMiddleware())
	optional.Use(authgo.GinOptionalProjectMiddleware("demo-service"))
	{
		optional.GET("/data", getMixedData)
	}

	log.Println("Starting demo server on :8081")
	log.Println("Available endpoints:")
	log.Println("  GET /health - Health check")
	log.Println("  GET /public/info - Service info")
	log.Println("  GET /user/profile - User profile (JWT required)")
	log.Println("  GET /user/permissions - User permissions (JWT required)")
	log.Println("  GET /api/v1/projects - Projects (project token required)")
	log.Println("  GET /api/v1/services - Services (project token required)")
	log.Println("  POST /api/v1/services - Create service (project token + scopes required)")
	log.Println("  DELETE /api/v1/services/:id - Delete service (project token + scopes required)")
	log.Println("  GET /mixed/data - Mixed data (optional auth)")

	if err := r.Run(":8081"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func getUserProfile(c *gin.Context) {
	user := authgo.GinMustGetAuthUser(c)
	
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":    user.UUID,
			"email": user.Email,
			"name":  user.Name,
		},
		"tenant_id": user.TenantID,
	})
}

func getUserPermissions(c *gin.Context) {
	user := authgo.GinMustGetAuthUser(c)
	
	c.JSON(http.StatusOK, gin.H{
		"permissions": user.Permissions,
		"token_id":    user.TokenID,
	})
}

func getProjects(c *gin.Context) {
	authReq, ok := authgo.GinGetAuthenticatedRequest(c)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "authentication context not found"})
		return
	}

	var tenantID string
	var tokenType string

	if authReq.Platform != nil {
		tenantID = authReq.Platform.TenantID
		tokenType = "platform"
	} else if authReq.Project != nil {
		tenantID = authReq.Project.TenantID
		tokenType = "project"
	} else if authReq.Service != nil {
		tenantID = "service-" + authReq.Service.ClientID
		tokenType = "service"
	}

	c.JSON(http.StatusOK, gin.H{
		"projects": []gin.H{
			{"id": "1", "name": "Demo Project 1", "tenant_id": tenantID},
			{"id": "2", "name": "Demo Project 2", "tenant_id": tenantID},
		},
		"auth_type": tokenType,
	})
}

func getServices(c *gin.Context) {
	project, ok := authgo.GinGetProjectContext(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "project context required"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"services":         []string{"service-a", "service-b", "service-c"},
		"enabled_services": project.EnabledServices,
		"scopes":          project.Scopes,
	})
}

func createService(c *gin.Context) {
	project := authgo.GinMustGetProjectContext(c)
	
	c.JSON(http.StatusCreated, gin.H{
		"message":    "Service created successfully",
		"project_id": project.ProjectUUID,
		"scopes":     project.Scopes,
	})
}

func deleteService(c *gin.Context) {
	serviceID := c.Param("id")
	project := authgo.GinMustGetProjectContext(c)
	
	c.JSON(http.StatusOK, gin.H{
		"message":    "Service deleted successfully",
		"service_id": serviceID,
		"project_id": project.ProjectUUID,
	})
}

func getMixedData(c *gin.Context) {
	response := gin.H{
		"public_data": "This is available to everyone",
		"timestamp":   gin.H{"iso": "2024-01-01T00:00:00Z"},
	}

	// Add user data if JWT auth is present
	if user, ok := authgo.GinGetAuthUser(c); ok {
		response["user_data"] = gin.H{
			"user_id": user.UUID,
			"email":   user.Email,
		}
	}

	// Add project data if project auth is present
	if project, ok := authgo.GinGetProjectContext(c); ok {
		response["project_data"] = gin.H{
			"tenant_id": project.TenantID,
			"scopes":    project.Scopes,
		}
	}

	c.JSON(http.StatusOK, response)
}

func setDemoEnvironment() {
	// Set default values for demo (override with real values in production)
	envDefaults := map[string]string{
		"MERCURY_BASE_URL":          "http://localhost:4000",
		"SIGNATURE_SHARED_SECRET":   "demo-secret-key-change-in-production",
		"REDIS_URL":                "localhost:6379",
		"CLIENT_ID":                "demo-client-id",
		"CLIENT_SECRET":            "demo-client-secret",
		"CACHE_EXPIRY_TIME":        "3600",
		"JWKS_CACHE_TTL":           "18000",
		"LOG_LEVEL":                "info",
	}

	for key, defaultValue := range envDefaults {
		if os.Getenv(key) == "" {
			os.Setenv(key, defaultValue)
		}
	}

	log.Println("Demo environment configured with default values")
	log.Println("Set the following environment variables for production:")
	for key := range envDefaults {
		log.Printf("  %s", key)
	}
}