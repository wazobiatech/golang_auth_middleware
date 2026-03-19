package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/client"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// Example service that verifies different token types and makes authenticated service calls

// AuthService handles token verification and service-to-service communication
type AuthService struct {
	jwtAuth       *auth.JwtAuthMiddleware
	projectAuth   *auth.ProjectAuthMiddleware
	serviceClient *client.ServiceClient
}

// VerifyPlatformToken verifies a platform token and returns the platform context
func (s *AuthService) VerifyPlatformToken(ctx *gin.Context) (*types.PlatformContext, error) {
	// Use ProjectAuthMiddleware to handle platform token (same header)
	authReq, err := s.projectAuth.Authenticate(ctx.Request)
	if err != nil {
		return nil, err
	}

	if authReq.Platform == nil {
		return nil, fmt.Errorf("token is not a platform token")
	}

	return authReq.Platform, nil
}

// VerifyUserToken verifies a user JWT token and returns the user context
func (s *AuthService) VerifyUserToken(ctx *gin.Context) (*types.AuthUser, error) {
	return s.jwtAuth.Authenticate(ctx.Request)
}

// CallProtectedService makes an authenticated call to another service
func (s *AuthService) CallProtectedService(targetServiceURL, endpoint, token string, method string) (map[string]interface{}, error) {
	// Generate a service token for authentication
	accessToken, err := s.serviceClient.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate service token: %w", err)
	}

	// Make the authenticated request
	client := &http.Client{}
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", targetServiceURL, endpoint), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication headers
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Set("x-project-token", fmt.Sprintf("Bearer %s", token)) // Forward original token if needed

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("service returned status %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// MultiTokenValidationService verifies different token types and provides a unified interface
type MultiTokenValidationService struct {
	jwtAuth     *auth.JwtAuthMiddleware
	projectAuth *auth.ProjectAuthMiddleware
}

// ValidateToken validates any token type and returns the appropriate context
func (s *MultiTokenValidationService) ValidateToken(ctx *gin.Context) (*types.AuthenticatedRequest, error) {
	// First try JWT token (Authorization header)
	token := ctx.GetHeader("Authorization")
	if token != "" {
		user, err := s.jwtAuth.Authenticate(ctx.Request)
		if err == nil {
			// Successfully authenticated as user
			return &types.AuthenticatedRequest{
				User: user,
			}, nil
		}
	}

	// Try project token (x-project-token header)
	token = ctx.GetHeader("x-project-token")
	if token != "" {
		authReq, err := s.projectAuth.Authenticate(ctx.Request)
		if err == nil {
			return authReq, nil
		}
	}

	return nil, fmt.Errorf("invalid or missing authentication token")
}

// ProtectedServiceExample simulates a protected API that accepts platform tokens
func ProtectedServiceExample() *gin.Engine {
	r := gin.Default()

	// Initialize auth services
	authService := &AuthService{
		jwtAuth:       auth.NewJwtAuthMiddleware(),
		projectAuth:   auth.NewProjectAuthMiddleware("platform-service"),
		serviceClient: client.NewServiceClient(),
	}

	multiAuth := &MultiTokenValidationService{
		jwtAuth:     auth.NewJwtAuthMiddleware(),
		projectAuth: auth.NewProjectAuthMiddleware("multi-auth-service"),
	}

	// Public endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "healthy"})
	})

	// Platform-scoped routes
	platform := r.Group("/api/platform")
	platform.Use(func(c *gin.Context) {
		// Verify platform token
		platformContext, err := authService.VerifyPlatformToken(c)
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid platform token", "details": err.Error()})
			c.Abort()
			return
		}

		// Store platform context for use in handlers
		c.Set("platform", platformContext)
		c.Next()
	})
	{
		platform.GET("/admin/users", func(c *gin.Context) {
			platform := c.MustGet("platform").(*types.PlatformContext)
			c.JSON(200, gin.H{
				"message": "Admin users retrieved",
				"platform": gin.H{
					"tenant_id": platform.TenantID,
					"scopes": platform.Scopes,
				},
				"users": []string{"admin1@wazobia.tech", "admin2@wazobia.tech"},
			})
		})

		platform.POST("/projects/create", func(c *gin.Context) {
			platform := c.MustGet("platform").(*types.PlatformContext)
			
			// Verify platform has required scope
			hasScope := false
			for _, scope := range platform.Scopes {
				if scope == "platform:admin" {
					hasScope = true
					break
				}
			}

			if !hasScope {
				c.JSON(403, gin.H{"error": "Insufficient permissions", "required": "platform:admin"})
				return
			}

			c.JSON(201, gin.H{
				"message": "Project created successfully",
				"project_id": "proj_123",
				"platform": gin.H{
					"tenant_id": platform.TenantID,
				},
			})
		})
	}

	// Multi-token validation endpoint
	r.POST("/api/validate-token", func(c *gin.Context) {
		var req struct {
			Token     string `json:"token"`
			TokenType string `json:"token_type"` // "user", "platform", "project", "service"
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(400, gin.H{"error": "Invalid request", "details": err.Error()})
			return
		}

		// For demonstration, extract from headers
		var token string
		if req.TokenType == "user" {
			token = c.GetHeader("Authorization")
			token = strings.TrimPrefix(token, "Bearer ")
		} else {
			token = c.GetHeader("x-project-token")
			token = strings.TrimPrefix(token, "Bearer ")
		}

		if token == "" && req.Token != "" {
			token = req.Token
		}

		// Use the multi-auth service
		c.Request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		authReq, err := multiAuth.ValidateToken(c)
		if err != nil {
			c.JSON(401, gin.H{"error": "Token validation failed", "details": err.Error()})
			return
		}

		response := gin.H{
			"valid": true,
			"token_type": "unknown",
		}

		if authReq.User != nil {
			response["token_type"] = "user"
			response["user"] = authReq.User
		} else if authReq.Platform != nil {
			response["token_type"] = "platform"
			response["platform"] = authReq.Platform
		} else if authReq.Project != nil {
			response["token_type"] = "project"
			response["project"] = authReq.Project
		} else if authReq.Service != nil {
			response["token_type"] = "service"
			response["service"] = authReq.Service
		}

		c.JSON(200, response)
	})

	// Service-to-service call example
	r.GET("/api/service/call-protected", func(c *gin.Context) {
		// Verify caller has permission to call other services
		platformContext, err := authService.VerifyPlatformToken(c)
		if err != nil {
			c.JSON(401, gin.H{"error": "Authentication required", "details": err.Error()})
			return
		}

		// Check if platform has admin:service scope
		hasScope := false
		for _, scope := range platformContext.Scopes {
			if strings.Contains(scope, "admin:service") || strings.Contains(scope, "platform:admin") {
				hasScope = true
				break
			}
		}

		if !hasScope {
			c.JSON(403, gin.H{"error": "Insufficient permissions", "required": "admin:service or platform:admin scope"})
			return
		}

		// The x-project-token from the incoming request (for forwarding)
		originalToken := c.GetHeader("x-project-token")

		// Call another protected service
		result, err := authService.CallProtectedService(
			"http://localhost:8081", // Target service URL
			"/api/internal/data",
			originalToken,
			"GET",
		)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to call protected service", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{
			"message": "Successfully called protected service",
			"called_by": gin.H{
				"tenant_id": platformContext.TenantID,
				"scopes": platformContext.Scopes,
			},
			"target_service_response": result,
		})
	})

	return r
}

func main() {
	r := ProtectedServiceExample()

	fmt.Println("🚀 Platform & Service Verification API running on :8080")
	fmt.Println("\nAvailable endpoints:")
	fmt.Println("  GET  /health                           - Health check")
	fmt.Println("  GET  /api/platform/admin/users         - Platform users (requires platform token)")
	fmt.Println("  POST /api/platform/projects/create     - Create project (platform:admin scope)")
	fmt.Println("  POST /api/validate-token               - Multi-token validation")
	fmt.Println("  GET  /api/service/call-protected       - Call protected service")
	fmt.Println("\nEnvironment variables required:")
	fmt.Println("  REDIS_URL, MERCURY_BASE_URL, SIGNATURE_SHARED_SECRET")
	fmt.Println("  CLIENT_ID, CLIENT_SECRET (for service auth)")

	log.Fatal(r.Run(":8080"))
}
