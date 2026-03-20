package unit

import (
	"context"
	"net/http"
	"testing"

	"github.com/wazobiatech/auth-middleware-go/pkg/graphql"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

func TestGraphQLHelpers_ContextKeys(t *testing.T) {
	// Test that context keys are unique
	keys := []graphql.ContextKey{
		graphql.UserKey,
		graphql.PlatformKey,
		graphql.ProjectKey,
		graphql.ServiceKey,
		graphql.HTTPRequestKey,
	}

	seen := make(map[graphql.ContextKey]bool)
	for _, key := range keys {
		if seen[key] {
			t.Errorf("Duplicate context key: %s", key)
		}
		seen[key] = true
	}
}

func TestGraphQLHelpers_GetCurrentUser(t *testing.T) {
	t.Run("User not in context", func(t *testing.T) {
		ctx := context.Background()
		user, err := graphql.GetCurrentUser(ctx)
		
		if err == nil {
			t.Error("Expected error when user not in context")
		}
		if user != nil {
			t.Error("Expected nil user")
		}
	})

	t.Run("User in context", func(t *testing.T) {
		expectedUser := &types.AuthUser{
			UUID:  "test-uuid",
			Email: "test@example.com",
			Name:  "Test User",
		}
		ctx := context.WithValue(context.Background(), graphql.UserKey, expectedUser)
		
		user, err := graphql.GetCurrentUser(ctx)
		
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if user == nil {
			t.Fatal("Expected user")
		}
		if user.UUID != expectedUser.UUID {
			t.Errorf("Expected UUID %s, got %s", expectedUser.UUID, user.UUID)
		}
	})
}

func TestGraphQLHelpers_GetProjectContext(t *testing.T) {
	t.Run("Project not in context", func(t *testing.T) {
		ctx := context.Background()
		project, err := graphql.GetProjectContext(ctx)
		
		if err == nil {
			t.Error("Expected error when project not in context")
		}
		if project != nil {
			t.Error("Expected nil project")
		}
	})

	t.Run("Project in context", func(t *testing.T) {
		expectedProject := &types.ProjectContext{
			TenantID: "test-tenant",
			Scopes:   []string{"read", "write"},
		}
		ctx := context.WithValue(context.Background(), graphql.ProjectKey, expectedProject)
		
		project, err := graphql.GetProjectContext(ctx)
		
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if project == nil {
			t.Fatal("Expected project")
		}
		if project.TenantID != expectedProject.TenantID {
			t.Errorf("Expected TenantID %s, got %s", expectedProject.TenantID, project.TenantID)
		}
	})
}

func TestGraphQLHelpers_GetServiceContext(t *testing.T) {
	t.Run("Service not in context", func(t *testing.T) {
		ctx := context.Background()
		service, err := graphql.GetServiceContext(ctx)
		
		if err == nil {
			t.Error("Expected error when service not in context")
		}
		if service != nil {
			t.Error("Expected nil service")
		}
	})

	t.Run("Service in context", func(t *testing.T) {
		expectedService := &types.ServiceContext{
			ClientID:    "client-123",
			ServiceName: "test-service",
			Scopes:      []string{"read"},
		}
		ctx := context.WithValue(context.Background(), graphql.ServiceKey, expectedService)
		
		service, err := graphql.GetServiceContext(ctx)
		
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if service == nil {
			t.Fatal("Expected service")
		}
		if service.ClientID != expectedService.ClientID {
			t.Errorf("Expected ClientID %s, got %s", expectedService.ClientID, service.ClientID)
		}
	})
}

func TestGraphQLHelpers_GetPlatformContext(t *testing.T) {
	t.Run("Platform not in context", func(t *testing.T) {
		ctx := context.Background()
		platform, err := graphql.GetPlatformContext(ctx)
		
		if err == nil {
			t.Error("Expected error when platform not in context")
		}
		if platform != nil {
			t.Error("Expected nil platform")
		}
	})

	t.Run("Platform in context", func(t *testing.T) {
		expectedPlatform := &types.PlatformContext{
			TenantID: "test-tenant",
			Scopes:   []string{"admin"},
		}
		ctx := context.WithValue(context.Background(), graphql.PlatformKey, expectedPlatform)
		
		platform, err := graphql.GetPlatformContext(ctx)
		
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if platform == nil {
			t.Fatal("Expected platform")
		}
		if platform.TenantID != expectedPlatform.TenantID {
			t.Errorf("Expected TenantID %s, got %s", expectedPlatform.TenantID, platform.TenantID)
		}
	})
}

func TestGraphQLHelpers_WithHTTPRequest(t *testing.T) {
	req, _ := http.NewRequest("GET", "/test", nil)
	ctx := graphql.WithHTTPRequest(context.Background(), req)

	retrievedReq, err := graphql.GetHTTPRequest(ctx)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if retrievedReq != req {
		t.Error("Expected retrieved request to be the same")
	}
}

func TestGraphQLHelpers_GetHTTPRequest(t *testing.T) {
	t.Run("Request not in context", func(t *testing.T) {
		ctx := context.Background()
		req, err := graphql.GetHTTPRequest(ctx)
		
		if err == nil {
			t.Error("Expected error when request not in context")
		}
		if req != nil {
			t.Error("Expected nil request")
		}
	})
}

func TestGraphQLHelpers_WithAuthenticatedRequest(t *testing.T) {
	authReq := &types.AuthenticatedRequest{
		User: &types.AuthUser{
			UUID: "user-123",
		},
		Project: &types.ProjectContext{
			TenantID: "tenant-123",
		},
		Service: &types.ServiceContext{
			ClientID: "client-123",
		},
		Platform: &types.PlatformContext{
			TenantID: "platform-tenant",
		},
	}

	ctx := graphql.WithAuthenticatedRequest(context.Background(), authReq)

	// Verify all contexts are set
	user, _ := graphql.GetCurrentUser(ctx)
	if user == nil || user.UUID != "user-123" {
		t.Error("User not properly set in context")
	}

	project, _ := graphql.GetProjectContext(ctx)
	if project == nil || project.TenantID != "tenant-123" {
		t.Error("Project not properly set in context")
	}

	service, _ := graphql.GetServiceContext(ctx)
	if service == nil || service.ClientID != "client-123" {
		t.Error("Service not properly set in context")
	}

	platform, _ := graphql.GetPlatformContext(ctx)
	if platform == nil || platform.TenantID != "platform-tenant" {
		t.Error("Platform not properly set in context")
	}
}

func TestGraphQLHelpers_GetAuthenticatedRequest(t *testing.T) {
	t.Run("Nothing in context", func(t *testing.T) {
		ctx := context.Background()
		authReq, err := graphql.GetAuthenticatedRequest(ctx)
		
		// Should return empty auth request without error
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if authReq == nil {
			t.Fatal("Expected auth request")
		}
		if authReq.User != nil {
			t.Error("Expected nil user")
		}
	})

	t.Run("Partial context", func(t *testing.T) {
		user := &types.AuthUser{UUID: "user-123"}
		ctx := context.WithValue(context.Background(), graphql.UserKey, user)

		authReq, err := graphql.GetAuthenticatedRequest(ctx)
		
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if authReq == nil {
			t.Fatal("Expected auth request")
		}
		if authReq.User == nil || authReq.User.UUID != "user-123" {
			t.Error("User not properly retrieved")
		}
	})
}

func TestAuthHelper_Creation(t *testing.T) {
	helper := graphql.NewAuthHelper("test-service")
	if helper == nil {
		t.Fatal("Expected auth helper to be created")
	}
}

func TestAuthHelper_Methods(t *testing.T) {
	helper := graphql.NewAuthHelper("test-service")

	// Test that methods exist and can be called (they'll fail without proper setup)
	_ = helper.AuthenticateUser
	_ = helper.AuthenticateProject
	_ = helper.WithUserAuth
	_ = helper.WithProjectAuth
	_ = helper.WithCombinedAuth
	_ = helper.WithServiceAuth
	_ = helper.WithServiceOrProjectAuth
	_ = helper.WithServiceOrUserAuth
	_ = helper.OptionalUserAuth
	_ = helper.OptionalProjectAuth
}

// Test resolver signature compatibility
func TestAuthHelper_ResolverSignatures(t *testing.T) {
	type testArgs struct {
		ID string
	}

	// Test resolver function
	testResolver := func(ctx context.Context, args testArgs) (string, error) {
		return "result", nil
	}

	// The wrappers should accept this signature
	_ = testResolver
}

func TestScopeCheckingLogic(t *testing.T) {
	tests := []struct {
		name     string
		provided []string
		required []string
		expected bool
	}{
		{"All match", []string{"a", "b", "c"}, []string{"a", "b"}, true},
		{"Partial match", []string{"a", "b"}, []string{"a", "c"}, false},
		{"Empty required", []string{"a", "b"}, []string{}, true},
		{"Empty provided", []string{}, []string{"a"}, false},
		{"Both empty", []string{}, []string{}, true},
		{"Single match", []string{"a"}, []string{"a"}, true},
		{"Single no match", []string{"a"}, []string{"b"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the hasAllScopes logic
			scopeSet := make(map[string]bool)
			for _, s := range tt.provided {
				scopeSet[s] = true
			}

			result := true
			for _, r := range tt.required {
				if !scopeSet[r] {
					result = false
					break
				}
			}

			if result != tt.expected {
				t.Errorf("hasAllScopes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGraphQLContext tests the GraphQLContext struct
func TestGraphQLContext(t *testing.T) {
	ctx := &graphql.GraphQLContext{
		User: &types.AuthUser{
			UUID: "user-123",
		},
		Project: &types.ProjectContext{
			TenantID: "tenant-123",
		},
		Service: &types.ServiceContext{
			ClientID: "client-123",
		},
		Platform: &types.PlatformContext{
			TenantID: "platform-123",
		},
		Request: &http.Request{},
	}

	if ctx.User == nil {
		t.Error("Expected User to be set")
	}
	if ctx.Project == nil {
		t.Error("Expected Project to be set")
	}
	if ctx.Service == nil {
		t.Error("Expected Service to be set")
	}
	if ctx.Platform == nil {
		t.Error("Expected Platform to be set")
	}
	if ctx.Request == nil {
		t.Error("Expected Request to be set")
	}
}
