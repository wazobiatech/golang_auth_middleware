package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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

// TestJwtAuthMiddleware_Authenticate tests JWT token validation
func TestJwtAuthMiddleware_Authenticate(t *testing.T) {
	// Generate test keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyID := "test-key-id"
	jwksResponse := generateTestJWKS(privateKey, keyID)

	// Create mock JWKS server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(jwksResponse))
	}))
	defer server.Close()

	// Set up test environment
	utils.UpdateConfig(map[string]interface{}{
		"MERCURY_BASE_URL":        server.URL,
		"SIGNATURE_SHARED_SECRET": "test-secret",
		"REDIS_URL":               "localhost:63799",
	})

	// Create middleware
	middleware := NewJwtAuthMiddleware()

	t.Run("ValidUserToken", func(t *testing.T) {
		// Create a valid JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"sub": map[string]interface{}{
				"uuid":  "test-user-123",
				"email": "test@example.com",
				"name":  "Test User",
			},
			"tenant_id":   "tenant-456",
			"token_id":    "token-789",
			"type":        "access_token",
			"permissions": []interface{}{"users:read", "users:write"},
			"iat":         time.Now().Unix(),
			"exp":         time.Now().Add(time.Hour).Unix(),
			"iss":         server.URL,
			"aud":         server.URL,
		})

		// Add kid to header
		token.Header["kid"] = keyID

		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)

		// Create request with token
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		// Test authentication
		user, err := middleware.Authenticate(req)
		require.NoError(t, err)
		assert.Equal(t, "test-user-123", user.UUID)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "tenant-456", user.TenantID)
		assert.Contains(t, user.Permissions, "users:read")
	})

	t.Run("MissingAuthorizationHeader", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)

		_, err := middleware.Authenticate(req)
		assert.Error(t, err)

		authErr, ok := err.(*types.AuthError)
		assert.True(t, ok)
		assert.Equal(t, types.ErrCodeMissingHeader, authErr.Code)
	})

	t.Run("InvalidTokenFormat", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer invalid-token-format")

		_, err := middleware.Authenticate(req)
		assert.Error(t, err)
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodRS512, jwt.MapClaims{
			"sub": map[string]interface{}{
				"uuid":  "test-user-123",
				"email": "test@example.com",
			},
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
			"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired
			"iss": server.URL,
		})

		// Add kid to header
		token.Header["kid"] = keyID

		tokenString, err := token.SignedString(privateKey)
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		_, err = middleware.Authenticate(req)
		assert.Error(t, err)

		// The error might be wrapped, so we need to check the underlying error
		var authErr *types.AuthError
		if errors.As(err, &authErr) {
			assert.Equal(t, types.ErrCodeExpiredToken, authErr.Code)
		} else {
			// Fallback check if errors.As doesn't work as expected
			assert.Contains(t, err.Error(), "expired")
		}
	})
}

// generateTestJWKS generates a test JWKS response
func generateTestJWKS(privateKey *rsa.PrivateKey, keyID string) string {
	pubKey := privateKey.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pubKey)
	if err != nil {
		panic(err)
	}

	jwk := map[string]interface{}{
		"kty": "RSA",
		"kid": keyID,
		"use": "sig",
		"alg": "RS512",
		"n":   base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{0, 1, 0, 1}), // 65537
		"x5c": []string{base64.StdEncoding.EncodeToString(pubKeyBytes)},
	}

	jwks := map[string]interface{}{
		"keys": []interface{}{jwk},
	}

	jsonData, _ := json.Marshal(jwks)
	return string(jsonData)
}

// encodeToPEM encodes RSA private key to PEM format
func encodeToPEM(privateKey *rsa.PrivateKey) string {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})
	return string(privKeyPEM)
}
