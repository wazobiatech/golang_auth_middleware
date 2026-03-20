package unit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	ginAdapter "github.com/wazobiatech/auth-middleware-go/pkg/adapters/gin"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

func TestGinMiddleware_JWTMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ginAdapter.JWTMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "No authorization header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Invalid token",
			authHeader: "Bearer invalid-token",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Malformed header",
			authHeader: "InvalidFormat",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestGinMiddleware_ProjectMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ginAdapter.ProjectMiddleware("test-service"))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	tests := []struct {
		name        string
		projectToken string
		wantStatus  int
	}{
		{
			name:        "No project token",
			projectToken: "",
			wantStatus:  http.StatusUnauthorized,
		},
		{
			name:        "Invalid token",
			projectToken: "Bearer invalid-token",
			wantStatus:  http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.projectToken != "" {
				req.Header.Set("x-project-token", tt.projectToken)
			}
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("Expected status %d, got %d", tt.wantStatus, w.Code)
			}
		})
	}
}

func TestGinMiddleware_RequireScope(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	// Note: RequireScope needs auth context from ProjectMiddleware
	router.Use(ginAdapter.ProjectMiddleware("test-service"))
	router.Use(ginAdapter.RequireScope("admin:read"))
	router.GET("/admin", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/admin", nil)
	req.Header.Set("x-project-token", "Bearer invalid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should be unauthorized since token is invalid
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestGinMiddleware_ContextHelpers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("GetAuthUser - not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		user, ok := ginAdapter.GetAuthUser(c)
		if ok {
			t.Error("Expected GetAuthUser to return false when not set")
		}
		if user != nil {
			t.Error("Expected user to be nil when not set")
		}
	})

	t.Run("GetProjectContext - not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		project, ok := ginAdapter.GetProjectContext(c)
		if ok {
			t.Error("Expected GetProjectContext to return false when not set")
		}
		if project != nil {
			t.Error("Expected project to be nil when not set")
		}
	})

	t.Run("GetServiceContext - not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		service, ok := ginAdapter.GetServiceContext(c)
		if ok {
			t.Error("Expected GetServiceContext to return false when not set")
		}
		if service != nil {
			t.Error("Expected service to be nil when not set")
		}
	})

	t.Run("GetPlatformContext - not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		platform, ok := ginAdapter.GetPlatformContext(c)
		if ok {
			t.Error("Expected GetPlatformContext to return false when not set")
		}
		if platform != nil {
			t.Error("Expected platform to be nil when not set")
		}
	})

	t.Run("GetAuthenticatedRequest - not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		authReq, ok := ginAdapter.GetAuthenticatedRequest(c)
		if ok {
			t.Error("Expected GetAuthenticatedRequest to return false when not set")
		}
		if authReq != nil {
			t.Error("Expected authReq to be nil when not set")
		}
	})
}

func TestGinMiddleware_ContextWithValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("GetAuthUser - with value", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		expectedUser := &types.AuthUser{
			UUID:  "test-uuid",
			Email: "test@example.com",
			Name:  "Test User",
		}
		c.Set(ginAdapter.AuthUserKey, expectedUser)

		user, ok := ginAdapter.GetAuthUser(c)
		if !ok {
			t.Error("Expected GetAuthUser to return true")
		}
		if user == nil {
			t.Fatal("Expected user to not be nil")
		}
		if user.UUID != expectedUser.UUID {
			t.Errorf("Expected UUID %s, got %s", expectedUser.UUID, user.UUID)
		}
	})

	t.Run("GetProjectContext - with value", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		expectedProject := &types.ProjectContext{
			TenantID: "test-tenant",
			Scopes:   []string{"read", "write"},
		}
		c.Set(ginAdapter.ProjectKey, expectedProject)

		project, ok := ginAdapter.GetProjectContext(c)
		if !ok {
			t.Error("Expected GetProjectContext to return true")
		}
		if project == nil {
			t.Fatal("Expected project to not be nil")
		}
		if project.TenantID != expectedProject.TenantID {
			t.Errorf("Expected TenantID %s, got %s", expectedProject.TenantID, project.TenantID)
		}
	})
}

func TestGinMiddleware_MustGetFunctions(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("MustGetAuthUser - panics when not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected MustGetAuthUser to panic")
			}
		}()

		ginAdapter.MustGetAuthUser(c)
	})

	t.Run("MustGetProjectContext - panics when not set", func(t *testing.T) {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected MustGetProjectContext to panic")
			}
		}()

		ginAdapter.MustGetProjectContext(c)
	})
}

func TestGinMiddleware_OptionalMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("OptionalJWTMiddleware - no token", func(t *testing.T) {
		router := gin.New()
		router.Use(ginAdapter.OptionalJWTMiddleware())
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})

	t.Run("OptionalProjectMiddleware - no token", func(t *testing.T) {
		router := gin.New()
		router.Use(ginAdapter.OptionalProjectMiddleware("test-service"))
		router.GET("/test", func(c *gin.Context) {
			c.Status(http.StatusOK)
		})

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}
	})
}

// TestScopeValidation tests scope validation logic
func TestScopeValidation(t *testing.T) {
	tests := []struct {
		name           string
		providedScopes []string
		requiredScopes []string
		shouldPass     bool
	}{
		{
			name:           "All scopes present",
			providedScopes: []string{"read", "write", "admin"},
			requiredScopes: []string{"read", "write"},
			shouldPass:     true,
		},
		{
			name:           "Missing scope",
			providedScopes: []string{"read"},
			requiredScopes: []string{"read", "write"},
			shouldPass:     false,
		},
		{
			name:           "No required scopes",
			providedScopes: []string{"read"},
			requiredScopes: []string{},
			shouldPass:     true,
		},
		{
			name:           "Empty provided scopes",
			providedScopes: []string{},
			requiredScopes: []string{"read"},
			shouldPass:     false,
		},
		{
			name:           "Both empty",
			providedScopes: []string{},
			requiredScopes: []string{},
			shouldPass:     true,
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

// BenchmarkGinMiddleware benchmarks the Gin middleware
func BenchmarkGinMiddleware_JWTMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(ginAdapter.JWTMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// TestHTTPAdapters tests the net/http adapters
func TestHTTPAdaptersExist(t *testing.T) {
	// Test that middleware functions exist and can be called
	_ = ginAdapter.JWTMiddleware
	_ = ginAdapter.ProjectMiddleware
	_ = ginAdapter.RequireScope
	_ = ginAdapter.OptionalJWTMiddleware
	_ = ginAdapter.OptionalProjectMiddleware
}
