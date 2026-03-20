// Package tests provides comprehensive testing examples for the auth middleware library.
//
// This file demonstrates how to test:
// - JWT authentication
// - Project/Service/Platform authentication
// - Scope validation
// - GraphQL resolvers
// - Different framework adapters
//
// Run with: go test -v ./tests/...
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authmiddleware "github.com/wazobiatech/auth-middleware-go"
	"github.com/wazobiatech/auth-middleware-go/pkg/graphql"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// ==================== EXAMPLE 1: Testing JWT Authentication ====================

func Example_jwtAuthentication() {
	// This example shows how to test JWT authentication in your application

	// Setup
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Apply JWT middleware to protected routes
	router.Use(authmiddleware.GinJWTMiddleware())
	router.GET("/api/user", func(c *gin.Context) {
		user, _ := authmiddleware.GinGetAuthUser(c)
		c.JSON(200, gin.H{
			"uuid":  user.UUID,
			"email": user.Email,
		})
	})

	// Test with valid token (would need proper setup)
	req := httptest.NewRequest("GET", "/api/user", nil)
	req.Header.Set("Authorization", "Bearer your-jwt-token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
}

func TestExample_JWTAuthentication(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name          string
		authHeader    string
		expectedStatus int
	}{
		{
			name:           "Missing authorization header",
			authHeader:    "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token format",
			authHeader:    "InvalidFormat",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Malformed JWT",
			authHeader:    "Bearer not.a.valid.jwt",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Use(authmiddleware.GinJWTMiddleware())
			router.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// ==================== EXAMPLE 2: Testing Project Authentication ====================

func Example_projectAuthentication() {
	// This example shows how to test project token authentication

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Apply project middleware
	router.Use(authmiddleware.GinProjectMiddleware("my-service"))
	router.GET("/api/data", func(c *gin.Context) {
		project, _ := authmiddleware.GinGetProjectContext(c)
		c.JSON(200, gin.H{
			"tenant_id": project.TenantID,
			"scopes":    project.Scopes,
		})
	})
}

func TestExample_ProjectAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		projectToken   string
		expectedStatus int
	}{
		{
			name:           "Missing project token",
			projectToken:   "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid token",
			projectToken:   "Bearer invalid-token",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.Use(authmiddleware.GinProjectMiddleware("test-service"))
			router.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest("GET", "/test", nil)
			if tt.projectToken != "" {
				req.Header.Set("x-project-token", tt.projectToken)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// ==================== EXAMPLE 3: Testing Scope Validation ====================

func Example_scopeValidation() {
	// This example shows how to test scope/permission validation

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Chain middleware: Project auth + Scope check
	router.Use(
		authmiddleware.GinProjectMiddleware("my-service"),
		authmiddleware.GinRequireScope("admin:read", "admin:write"),
	)
	router.GET("/api/admin", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Admin access granted"})
	})
}

func TestExample_ScopeValidation(t *testing.T) {
	// Test the scope checking logic directly
	tests := []struct {
		name           string
		providedScopes []string
		requiredScopes []string
		shouldPass     bool
	}{
		{
			name:           "Has all required scopes",
			providedScopes: []string{"read", "write", "admin"},
			requiredScopes: []string{"read", "write"},
			shouldPass:     true,
		},
		{
			name:           "Missing one scope",
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
			name:           "Required scope not in provided",
			providedScopes: []string{"read", "write"},
			requiredScopes: []string{"admin"},
			shouldPass:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate scope validation
			scopeSet := make(map[string]bool)
			for _, s := range tt.providedScopes {
				scopeSet[s] = true
			}

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

// ==================== EXAMPLE 4: Testing GraphQL Resolvers ====================

func Example_graphQLResolver() {
	// This example shows how to test GraphQL resolver authentication

	authHelper := authmiddleware.NewAuthHelper("my-service")

	// Wrap your resolver with authentication
	resolver := authHelper.WithUserAuth(
		func(ctx context.Context, args interface{}) (interface{}, error) {
			// Your resolver logic here
			user, _ := authmiddleware.GraphQLGetCurrentUser(ctx)
			return map[string]string{
				"uuid":  user.UUID,
				"email": user.Email,
			}, nil
		},
		"user:read", // Required scopes
	)

	_ = resolver
}

func TestExample_GraphQLContext(t *testing.T) {
	// Test setting and getting values from GraphQL context

	ctx := context.Background()

	// Add user to context
	user := &types.AuthUser{
		UUID:        "user-123",
		Email:       "test@example.com",
		Permissions: []string{"read", "write"},
	}
	ctx = context.WithValue(ctx, graphql.UserKey, user)

	// Retrieve user
	retrievedUser, err := graphql.GetCurrentUser(ctx)
	if err != nil {
		t.Errorf("Failed to get user: %v", err)
	}
	if retrievedUser.UUID != user.UUID {
		t.Errorf("Expected UUID %s, got %s", user.UUID, retrievedUser.UUID)
	}

	// Test WithHTTPRequest
	req, _ := http.NewRequest("GET", "/graphql", nil)
	ctx = graphql.WithHTTPRequest(ctx, req)

	retrievedReq, err := graphql.GetHTTPRequest(ctx)
	if err != nil {
		t.Errorf("Failed to get request: %v", err)
	}
	if retrievedReq != req {
		t.Error("Expected same request object")
	}
}

// ==================== EXAMPLE 5: Testing Different Token Types ====================

func TestExample_TokenTypes(t *testing.T) {
	tests := []struct {
		name        string
		setupAuth   func() *types.AuthenticatedRequest
		checkFunc   func(*types.AuthenticatedRequest) bool
	}{
		{
			name: "Platform token",
			setupAuth: func() *types.AuthenticatedRequest {
				return &types.AuthenticatedRequest{
					Platform: &types.PlatformContext{
						TenantID: "platform-tenant",
						Scopes:   []string{"admin"},
					},
				}
			},
			checkFunc: func(r *types.AuthenticatedRequest) bool {
				return r.Platform != nil && r.Project == nil && r.Service == nil
			},
		},
		{
			name: "Project token",
			setupAuth: func() *types.AuthenticatedRequest {
				return &types.AuthenticatedRequest{
					Project: &types.ProjectContext{
						TenantID: "project-tenant",
						Scopes:   []string{"read", "write"},
					},
				}
			},
			checkFunc: func(r *types.AuthenticatedRequest) bool {
				return r.Project != nil && r.Platform == nil && r.Service == nil
			},
		},
		{
			name: "Service token",
			setupAuth: func() *types.AuthenticatedRequest {
				return &types.AuthenticatedRequest{
					Service: &types.ServiceContext{
						ClientID:    "client-123",
						ServiceName: "my-service",
						Scopes:      []string{"internal:read"},
					},
				}
			},
			checkFunc: func(r *types.AuthenticatedRequest) bool {
				return r.Service != nil && r.Platform == nil && r.Project == nil
			},
		},
		{
			name: "User token",
			setupAuth: func() *types.AuthenticatedRequest {
				return &types.AuthenticatedRequest{
					User: &types.AuthUser{
						UUID:        "user-123",
						Email:       "user@example.com",
						Permissions: []string{"read"},
					},
				}
			},
			checkFunc: func(r *types.AuthenticatedRequest) bool {
				return r.User != nil && r.Platform == nil && r.Project == nil && r.Service == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authReq := tt.setupAuth()
			if !tt.checkFunc(authReq) {
				t.Errorf("Token type check failed for %s", tt.name)
			}
		})
	}
}

// ==================== EXAMPLE 6: Testing Error Handling ====================

func TestExample_ErrorHandling(t *testing.T) {
	// Test creating and handling auth errors

	tests := []struct {
		name     string
		error    *types.AuthError
		expected string
	}{
		{
			name:     "Invalid token",
			error:    types.NewAuthError(types.ErrCodeInvalidToken, "Token is invalid"),
			expected: "Token is invalid",
		},
		{
			name:     "Expired token",
			error:    types.NewAuthError(types.ErrCodeExpiredToken, "Token has expired"),
			expected: "Token has expired",
		},
		{
			name:     "Missing header",
			error:    types.NewAuthError(types.ErrCodeMissingHeader, "Authorization header missing"),
			expected: "Authorization header missing",
		},
		{
			name:     "Insufficient scope",
			error:    types.NewAuthError(types.ErrCodeInsufficientScope, "Insufficient permissions"),
			expected: "Insufficient permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.error.Error() != tt.expected {
				t.Errorf("Expected error message '%s', got '%s'", tt.expected, tt.error.Error())
			}

			// Test JSON marshaling
			jsonData, err := json.Marshal(tt.error)
			if err != nil {
				t.Errorf("Failed to marshal error: %v", err)
			}

			var unmarshaled types.AuthError
			if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
				t.Errorf("Failed to unmarshal error: %v", err)
			}

			if unmarshaled.Code != tt.error.Code {
				t.Errorf("Expected code '%s', got '%s'", tt.error.Code, unmarshaled.Code)
			}
		})
	}
}

// ==================== EXAMPLE 7: Mocking for Unit Tests ====================

// MockAuthMiddleware is a mock implementation for unit testing
type MockAuthMiddleware struct {
	AuthenticateUserFunc    func(r *http.Request) (*types.AuthUser, error)
	AuthenticateProjectFunc func(r *http.Request) (*types.AuthenticatedRequest, error)
}

func (m *MockAuthMiddleware) AuthenticateUser(r *http.Request) (*types.AuthUser, error) {
	if m.AuthenticateUserFunc != nil {
		return m.AuthenticateUserFunc(r)
	}
	return nil, types.NewAuthError(types.ErrCodeInvalidToken, "mock error")
}

func (m *MockAuthMiddleware) AuthenticateProject(r *http.Request) (*types.AuthenticatedRequest, error) {
	if m.AuthenticateProjectFunc != nil {
		return m.AuthenticateProjectFunc(r)
	}
	return nil, types.NewAuthError(types.ErrCodeInvalidToken, "mock error")
}

func TestExample_MockMiddleware(t *testing.T) {
	// Example of using mock middleware for unit testing

	mock := &MockAuthMiddleware{
		AuthenticateUserFunc: func(r *http.Request) (*types.AuthUser, error) {
			return &types.AuthUser{
				UUID:  "mock-uuid",
				Email: "mock@example.com",
				Name:  "Mock User",
			}, nil
		},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	user, err := mock.AuthenticateUser(req)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if user.UUID != "mock-uuid" {
		t.Errorf("Expected UUID 'mock-uuid', got '%s'", user.UUID)
	}
}

// ==================== EXAMPLE 8: Testing HTTP Response Format ====================

func TestExample_HTTPResponseFormat(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(authmiddleware.GinJWTMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Check response format
	if w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Errorf("Expected JSON content type, got %s", w.Header().Get("Content-Type"))
	}

	// Parse error response
	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse response: %v", err)
	}

	if _, hasError := response["error"]; !hasError {
		t.Error("Expected 'error' field in response")
	}
	if _, hasMessage := response["message"]; !hasMessage {
		t.Error("Expected 'message' field in response")
	}
}

// ==================== EXAMPLE 9: Testing with Request Body ====================

func TestExample_WithRequestBody(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(authmiddleware.GinProjectMiddleware("test-service"))
	router.POST("/api/data", func(c *gin.Context) {
		var body map[string]interface{}
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid body"})
			return
		}
		c.JSON(http.StatusOK, body)
	})

	// Create request with body
	bodyData := map[string]string{"key": "value"}
	bodyBytes, _ := json.Marshal(bodyData)
	req := httptest.NewRequest("POST", "/api/data", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-project-token", "Bearer test-token")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Note: Will be unauthorized due to invalid token, but tests the flow
	if w.Code != http.StatusUnauthorized {
		t.Logf("Request body test - Status: %d", w.Code)
	}
}

// ==================== EXAMPLE 10: Complete Integration Test ====================

func TestExample_CompleteIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Public route
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Protected routes
	api := router.Group("/api")
	api.Use(authmiddleware.GinProjectMiddleware("my-service"))
	{
		api.GET("/data", func(c *gin.Context) {
			project, _ := authmiddleware.GinGetProjectContext(c)
			c.JSON(http.StatusOK, gin.H{
				"tenant_id": project.TenantID,
				"message":   "Success",
			})
		})

		// Admin only route
		admin := api.Group("/admin")
		admin.Use(authmiddleware.GinRequireScope("admin:read"))
		{
			admin.GET("/users", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"users": []string{}})
			})
		}
	}

	// Test cases
	tests := []struct {
		name       string
		path       string
		headers    map[string]string
		wantStatus int
	}{
		{
			name:       "Health check - no auth",
			path:       "/health",
			headers:    map[string]string{},
			wantStatus: http.StatusOK,
		},
		{
			name:       "API without token",
			path:       "/api/data",
			headers:    map[string]string{},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "API with token",
			path:       "/api/data",
			headers:    map[string]string{"x-project-token": "Bearer test"},
			wantStatus: http.StatusUnauthorized, // Token invalid but tests flow
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}
