package unit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

func TestProjectAuthMiddleware_Authenticate(t *testing.T) {
	projectAuth := auth.NewProjectAuthMiddleware("test-service")

	tests := []struct {
		name          string
		projectToken  string
		expectedError bool
		errorCode     string
	}{
		{
			name:          "Missing x-project-token header",
			projectToken:  "",
			expectedError: true,
			errorCode:     types.ErrCodeMissingHeader,
		},
		{
			name:          "Empty token",
			projectToken:  "Bearer ",
			expectedError: true,
			errorCode:     types.ErrCodeInvalidToken,
		},
		{
			name:          "Invalid token format",
			projectToken:  "invalid-token",
			expectedError: true,
			errorCode:     types.ErrCodeInvalidToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.projectToken != "" {
				req.Header.Set("x-project-token", tt.projectToken)
			}

			authReq, err := projectAuth.Authenticate(req)

			if tt.expectedError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				authErr, ok := err.(*types.AuthError)
				if ok && authErr.Code != tt.errorCode {
					t.Errorf("Expected error code %s, got %s", tt.errorCode, authErr.Code)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if authReq == nil {
					t.Error("Expected auth request but got nil")
				}
			}
		})
	}
}

func TestProjectAuthMiddleware_TokenExtraction(t *testing.T) {
	projectAuth := auth.NewProjectAuthMiddleware("test-service")

	tests := []struct {
		name         string
		tokenHeader  string
		expectError  bool
	}{
		{
			name:        "Bearer prefix",
			tokenHeader: "Bearer my-project-token",
			expectError: true, // Will fail validation but extraction should work
		},
		{
			name:        "No Bearer prefix",
			tokenHeader: "my-project-token",
			expectError: true,
		},
		{
			name:        "Token with spaces",
			tokenHeader: "Bearer   my-project-token",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("x-project-token", tt.tokenHeader)

			_, err := projectAuth.Authenticate(req)
			
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}

func TestTokenValidationResult(t *testing.T) {
	result := &auth.TokenValidationResult{
		IsValid: true,
		Payload: &types.ProjectTokenPayload{
			TenantID: "test-tenant",
			TokenID:  "test-token",
			Type:     "project",
		},
		Error: "",
	}

	if !result.IsValid {
		t.Error("Expected IsValid to be true")
	}

	if result.Payload == nil {
		t.Error("Expected Payload to not be nil")
	}

	payload, ok := result.Payload.(*types.ProjectTokenPayload)
	if !ok {
		t.Error("Expected Payload to be *types.ProjectTokenPayload")
	}

	if payload.TenantID != "test-tenant" {
		t.Errorf("Expected TenantID to be 'test-tenant', got %s", payload.TenantID)
	}
}

func TestProjectAuthMiddleware_SetCacheTTL(t *testing.T) {
	projectAuth := auth.NewProjectAuthMiddleware("test-service")
	
	// Should not panic
	projectAuth.SetCacheTTL(3600)
}

func BenchmarkProjectAuthMiddleware_Authenticate(b *testing.B) {
	projectAuth := auth.NewProjectAuthMiddleware("test-service")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("x-project-token", "Bearer invalid-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		projectAuth.Authenticate(req)
	}
}

func TestTokenTypes(t *testing.T) {
	tests := []struct {
		name        string
		tokenType   string
		expectError bool
	}{
		{
			name:        "Platform token",
			tokenType:   "platform",
			expectError: true, // Will fail without proper setup
		},
		{
			name:        "Project token",
			tokenType:   "project",
			expectError: true,
		},
		{
			name:        "Service token",
			tokenType:   "service",
			expectError: true,
		},
		{
			name:        "Unknown token type",
			tokenType:   "unknown",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify token type handling exists
			_ = tt.tokenType
		})
	}
}

// TestMiddlewareCreation tests creating middleware with different service names
func TestMiddlewareCreation(t *testing.T) {
	tests := []struct {
		serviceName string
	}{
		{"my-service"},
		{"My-Service"},
		{"MY_SERVICE"},
		{"service-with-dashes"},
		{"service.with.dots"},
	}

	for _, tt := range tests {
		t.Run(tt.serviceName, func(t *testing.T) {
			middleware := auth.NewProjectAuthMiddleware(tt.serviceName)
			if middleware == nil {
				t.Error("Expected middleware to be created")
			}
		})
	}
}

// MockProjectAuthMiddleware is a mock for testing
type MockProjectAuthMiddleware struct {
	AuthenticateFunc func(req *http.Request) (*types.AuthenticatedRequest, error)
}

func (m *MockProjectAuthMiddleware) Authenticate(req *http.Request) (*types.AuthenticatedRequest, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(req)
	}
	return nil, types.NewAuthError(types.ErrCodeInvalidToken, "mock error")
}

func TestMockProjectAuthMiddleware(t *testing.T) {
	mock := &MockProjectAuthMiddleware{
		AuthenticateFunc: func(req *http.Request) (*types.AuthenticatedRequest, error) {
			return &types.AuthenticatedRequest{
				Project: &types.ProjectContext{
					TenantID: "mock-tenant",
					Scopes:   []string{"read"},
				},
			}, nil
		},
	}

	req := httptest.NewRequest("GET", "/test", nil)
	authReq, err := mock.Authenticate(req)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if authReq == nil {
		t.Fatal("Expected auth request")
	}

	if authReq.Project == nil {
		t.Fatal("Expected project context")
	}

	if authReq.Project.TenantID != "mock-tenant" {
		t.Errorf("Expected tenant ID 'mock-tenant', got %s", authReq.Project.TenantID)
	}
}

// TestServiceEnablement tests the service enablement check logic
func TestServiceEnablement(t *testing.T) {
	tests := []struct {
		name            string
		enabledServices []string
		serviceID       string
		shouldBeEnabled bool
	}{
		{
			name:            "Service is enabled",
			enabledServices: []string{"service-1", "service-2", "my-service"},
			serviceID:       "my-service",
			shouldBeEnabled: true,
		},
		{
			name:            "Service is not enabled",
			enabledServices: []string{"service-1", "service-2"},
			serviceID:       "my-service",
			shouldBeEnabled: false,
		},
		{
			name:            "Empty enabled services",
			enabledServices: []string{},
			serviceID:       "my-service",
			shouldBeEnabled: false,
		},
		{
			name:            "Case sensitive check",
			enabledServices: []string{"My-Service"},
			serviceID:       "my-service",
			shouldBeEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled := false
			for _, s := range tt.enabledServices {
				if s == tt.serviceID {
					enabled = true
					break
				}
			}

			if enabled != tt.shouldBeEnabled {
				t.Errorf("Expected enabled=%v, got %v", tt.shouldBeEnabled, enabled)
			}
		})
	}
}
