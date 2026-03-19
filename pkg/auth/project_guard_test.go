package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

func TestProjectAuthMiddleware_Authenticate(t *testing.T) {
	// Generate test keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyID := "test-key-id"
	jwksResponse := generateTestJWKS(privateKey, keyID)

	// Create mock server for JWKS and GraphQL
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/graphql" {
			// Mock GraphQL response for service validation
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"generateServiceToken": map[string]interface{}{
						"access_token": "mock-access-token",
						"token_type":   "Bearer",
						"expires_in":   3600,
					},
					"getRegisteredServiceByClientId": map[string]interface{}{
						"uuid": "test-service",
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Default to JWKS response
		w.Write([]byte(jwksResponse))
	}))
	defer server.Close()

	// Set up test environment
	utils.UpdateConfig(map[string]interface{}{
		"MERCURY_BASE_URL":        server.URL,
		"SIGNATURE_SHARED_SECRET": "test-secret",
		"CLIENT_ID":               "test-client",
		"CLIENT_SECRET":           "test-secret",
		"REDIS_URL":               "localhost:63799",
	})

	middleware := NewProjectAuthMiddleware("test-service")

	t.Run("ValidPlatformToken", func(t *testing.T) {
		// Create platform token
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"tenant_id":      "tenant-456",
			"secret_version": float64(1),
			"token_id":       "platform-token-123",
			"type":           "platform",
			"scopes":         []interface{}{"platform:admin", "users:manage"},
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iss":            server.URL,
			"aud":            server.URL,
		})

		// Add kid to header
		token.Header["kid"] = keyID

		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("x-project-token", "Bearer "+tokenString)

		authReq, err := middleware.Authenticate(req)
		require.NoError(t, err)
		require.NotNil(t, authReq.Platform)

		assert.Equal(t, "tenant-456", authReq.Platform.TenantID)
		assert.Equal(t, "platform-token-123", authReq.Platform.TokenID)
		assert.Contains(t, authReq.Platform.Scopes, "platform:admin")
	})

	t.Run("ValidProjectToken", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"tenant_id":        "tenant-456",
			"secret_version":   float64(1),
			"enabled_services": []interface{}{"test-service"},
			"token_id":         "project-token-789",
			"type":             "project",
			"scopes":           []interface{}{"projects:read", "projects:write"},
			"iat":              time.Now().Unix(),
			"exp":              time.Now().Add(time.Hour).Unix(),
			"iss":              server.URL,
			"aud":              "*",
		})

		// Add kid to header
		token.Header["kid"] = keyID

		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("x-project-token", "Bearer "+tokenString)

		authReq, err := middleware.Authenticate(req)
		require.NoError(t, err)
		require.NotNil(t, authReq.Project)

		assert.Equal(t, "tenant-456", authReq.Project.TenantID)
		assert.Equal(t, "project-token-789", authReq.Project.TokenID)
		assert.Contains(t, authReq.Project.EnabledServices, "test-service")
	})

	t.Run("MissingTokenHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)

		_, err := middleware.Authenticate(req)
		assert.Error(t, err)

		authErr, ok := err.(*types.AuthError)
		assert.True(t, ok)
		assert.Equal(t, types.ErrCodeMissingHeader, authErr.Code)
	})

	t.Run("InvalidTokenType", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"type": "invalid-type",
			"iat":  time.Now().Unix(),
			"exp":  time.Now().Add(time.Hour).Unix(),
		})

		// Add kid to header
		token.Header["kid"] = keyID

		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("x-project-token", "Bearer "+tokenString)

		_, err = middleware.Authenticate(req)
		assert.Error(t, err)
	})
}

func TestVerifyPlatformToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyID := "test-key-id"
	jwksResponse := generateTestJWKS(privateKey, keyID)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksResponse))
	}))
	defer server.Close()

	utils.UpdateConfig(map[string]interface{}{
		"MERCURY_BASE_URL": server.URL,
		"REDIS_URL":        "localhost:63799",
	})

	middleware := NewProjectAuthMiddleware("test-service")

	t.Run("ValidPlatformContext", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"tenant_id":      "tenant-456",
			"secret_version": float64(1),
			"token_id":       "platform-token-123",
			"type":           "platform",
			"scopes":         []interface{}{"platform:admin"},
			"iat":            time.Now().Unix(),
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iss":            server.URL,
			"aud":            server.URL,
		})

		// Add kid to header
		token.Header["kid"] = keyID

		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("x-project-token", "Bearer "+tokenString)

		authReq, err := middleware.Authenticate(req)
		require.NoError(t, err)
		require.NotNil(t, authReq.Platform)

		assert.Equal(t, "tenant-456", authReq.Platform.TenantID)
		assert.Equal(t, "platform-token-123", authReq.Platform.TokenID)
	})
}
