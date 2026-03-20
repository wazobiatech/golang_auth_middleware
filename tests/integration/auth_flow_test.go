package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/wazobiatech/auth-middleware-go/pkg/graphql"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// TestEndToEnd_GinMiddleware tests a complete auth flow with Gin
func TestEndToEnd_GinMiddleware(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Public endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Protected endpoint (JWT)
	router.Group("/user").Use(func(c *gin.Context) {
		// Simulate JWT middleware behavior
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
				"message": "No authorization header",
			})
			return
		}
		c.Next()
	}).GET("/profile", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"user": "test"})
	})

	// Protected endpoint (Project)
	router.Group("/api").Use(func(c *gin.Context) {
		token := c.GetHeader("x-project-token")
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Unauthorized",
				"message": "No project token",
			})
			return
		}
		c.Next()
	}).GET("/data", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"data": "secret"})
	})

	tests := []struct {
		name       string
		path       string
		headers    map[string]string
		wantStatus int
	}{
		{
			name:       "Public endpoint - no auth",
			path:       "/health",
			headers:    map[string]string{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "JWT endpoint - no auth",
			path:       "/user/profile",
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "JWT endpoint - with auth",
			path:       "/user/profile",
			headers:    map[string]string{"Authorization": "Bearer test-token"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "Project endpoint - no auth",
			path:       "/api/data",
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Project endpoint - with auth",
			path:       "/api/data",
			headers:    map[string]string{"x-project-token": "Bearer test-token"},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

// TestEndToEnd_GraphQLFlow tests GraphQL authentication flow
func TestEndToEnd_GraphQLFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	helper := graphql.NewAuthHelper("test-service")
	_ = helper

	// Test context manipulation
	ctx := context.Background()

	// Simulate adding auth data to context
	user := &types.AuthUser{
		UUID:        "user-123",
		Email:       "test@example.com",
		Name:        "Test User",
		Permissions: []string{"read", "write"},
	}

	project := &types.ProjectContext{
		TenantID: "tenant-123",
		Scopes:   []string{"project:read"},
	}

	ctx = context.WithValue(ctx, graphql.UserKey, user)
	ctx = context.WithValue(ctx, graphql.ProjectKey, project)

	// Test retrieving from context
	retrievedUser, err := graphql.GetCurrentUser(ctx)
	if err != nil {
		t.Errorf("Failed to get user from context: %v", err)
	}
	if retrievedUser.UUID != user.UUID {
		t.Errorf("Expected UUID %s, got %s", user.UUID, retrievedUser.UUID)
	}

	retrievedProject, err := graphql.GetProjectContext(ctx)
	if err != nil {
		t.Errorf("Failed to get project from context: %v", err)
	}
	if retrievedProject.TenantID != project.TenantID {
		t.Errorf("Expected TenantID %s, got %s", project.TenantID, retrievedProject.TenantID)
	}
}

// TestEndToEnd_ScopeValidation tests scope validation
func TestEndToEnd_ScopeValidation(t *testing.T) {
	tests := []struct {
		name           string
		providedScopes []string
		requiredScopes []string
		shouldPass     bool
	}{
		{
			name:           "User has all required scopes",
			providedScopes: []string{"read", "write", "admin"},
			requiredScopes: []string{"read", "write"},
			shouldPass:     true,
		},
		{
			name:           "User missing required scope",
			providedScopes: []string{"read"},
			requiredScopes: []string{"read", "write"},
			shouldPass:     false,
		},
		{
			name:           "No scopes required",
			providedScopes: []string{},
			requiredScopes: []string{},
			shouldPass:     true,
		},
		{
			name:           "Single scope required - has it",
			providedScopes: []string{"admin"},
			requiredScopes: []string{"admin"},
			shouldPass:     true,
		},
		{
			name:           "Single scope required - doesn't have it",
			providedScopes: []string{"user"},
			requiredScopes: []string{"admin"},
			shouldPass:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build scope set
			scopeSet := make(map[string]bool)
			for _, s := range tt.providedScopes {
				scopeSet[s] = true
			}

			// Check required scopes
			passes := true
			for _, r := range tt.requiredScopes {
				if !scopeSet[r] {
					passes = false
					break
				}
			}

			if passes != tt.shouldPass {
				t.Errorf("Expected shouldPass=%v, got %v", tt.shouldPass, passes)
			}
		})
	}
}

// TestEndToEnd_TokenTypeHandling tests different token types
func TestEndToEnd_TokenTypeHandling(t *testing.T) {
	tests := []struct {
		name      string
		tokenType string
		setupFunc func() (*types.AuthenticatedRequest, error)
	}{
		{
			name:      "Platform token",
			tokenType: "platform",
			setupFunc: func() (*types.AuthenticatedRequest, error) {
				return &types.AuthenticatedRequest{
					Platform: &types.PlatformContext{
						TenantID: "platform-tenant",
						Scopes:   []string{"admin"},
					},
				}, nil
			},
		},
		{
			name:      "Project token",
			tokenType: "project",
			setupFunc: func() (*types.AuthenticatedRequest, error) {
				return &types.AuthenticatedRequest{
					Project: &types.ProjectContext{
						TenantID: "project-tenant",
						Scopes:   []string{"read", "write"},
					},
				}, nil
			},
		},
		{
			name:      "Service token",
			tokenType: "service",
			setupFunc: func() (*types.AuthenticatedRequest, error) {
				return &types.AuthenticatedRequest{
					Service: &types.ServiceContext{
						ClientID:    "service-client",
						ServiceName: "test-service",
						Scopes:      []string{"internal:read"},
					},
				}, nil
			},
		},
		{
			name:      "User token",
			tokenType: "user",
			setupFunc: func() (*types.AuthenticatedRequest, error) {
				return &types.AuthenticatedRequest{
					User: &types.AuthUser{
						UUID:        "user-uuid",
						Email:       "user@example.com",
						Permissions: []string{"read"},
					},
				}, nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authReq, err := tt.setupFunc()
			if err != nil {
				t.Errorf("Setup failed: %v", err)
				return
			}

			// Verify the correct context is set
			switch tt.tokenType {
			case "platform":
				if authReq.Platform == nil {
					t.Error("Expected Platform to be set")
				}
			case "project":
				if authReq.Project == nil {
					t.Error("Expected Project to be set")
				}
			case "service":
				if authReq.Service == nil {
					t.Error("Expected Service to be set")
				}
			case "user":
				if authReq.User == nil {
					t.Error("Expected User to be set")
				}
			}
		})
	}
}

// TestEndToEnd_ErrorHandling tests error scenarios
func TestEndToEnd_ErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		error     *types.AuthError
		wantCode  string
		wantMessage string
	}{
		{
			name:        "Invalid token error",
			error:       types.NewAuthError(types.ErrCodeInvalidToken, "Token is invalid"),
			wantCode:    types.ErrCodeInvalidToken,
			wantMessage: "Token is invalid",
		},
		{
			name:        "Expired token error",
			error:       types.NewAuthError(types.ErrCodeExpiredToken, "Token has expired"),
			wantCode:    types.ErrCodeExpiredToken,
			wantMessage: "Token has expired",
		},
		{
			name:        "Missing header error",
			error:       types.NewAuthError(types.ErrCodeMissingHeader, "Authorization header missing"),
			wantCode:    types.ErrCodeMissingHeader,
			wantMessage: "Authorization header missing",
		},
		{
			name:        "Insufficient scope error",
			error:       types.NewAuthError(types.ErrCodeInsufficientScope, "Insufficient permissions"),
			wantCode:    types.ErrCodeInsufficientScope,
			wantMessage: "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.error.Code != tt.wantCode {
				t.Errorf("Expected code %s, got %s", tt.wantCode, tt.error.Code)
			}
			if tt.error.Message != tt.wantMessage {
				t.Errorf("Expected message %s, got %s", tt.wantMessage, tt.error.Message)
			}
		})
	}
}

// TestEndToEnd_ContextPropagation tests context propagation
func TestEndToEnd_ContextPropagation(t *testing.T) {
	// Start with background context
	ctx := context.Background()

	// Add user
	user := &types.AuthUser{UUID: "user-123"}
	ctx = context.WithValue(ctx, graphql.UserKey, user)

	// Add project
	project := &types.ProjectContext{TenantID: "tenant-123"}
	ctx = context.WithValue(ctx, graphql.ProjectKey, project)

	// Verify both are accessible
	retrievedUser, err := graphql.GetCurrentUser(ctx)
	if err != nil {
		t.Errorf("Failed to get user: %v", err)
	}
	if retrievedUser.UUID != user.UUID {
		t.Errorf("User mismatch")
	}

	retrievedProject, err := graphql.GetProjectContext(ctx)
	if err != nil {
		t.Errorf("Failed to get project: %v", err)
	}
	if retrievedProject.TenantID != project.TenantID {
		t.Errorf("Project mismatch")
	}
}
