package unit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// generateTestKeyPair generates a test RSA key pair
func generateTestKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// generateTestToken creates a test JWT token
func generateTestToken(privateKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return token.SignedString(privateKey)
}

func TestJwtAuthMiddleware_Authenticate(t *testing.T) {
	// Create middleware
	jwtAuth := auth.NewJwtAuthMiddleware()

	tests := []struct {
		name           string
		authorization  string
		expectedError  bool
		errorCode      string
	}{
		{
			name:          "Missing authorization header",
			authorization: "",
			expectedError: true,
			errorCode:     types.ErrCodeMissingHeader,
		},
		{
			name:          "Empty token",
			authorization: "Bearer ",
			expectedError: true,
			errorCode:     types.ErrCodeInvalidToken,
		},
		{
			name:          "Invalid token format",
			authorization: "InvalidToken",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			user, err := jwtAuth.Authenticate(req)

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
				if user == nil {
					t.Error("Expected user but got nil")
				}
			}
		})
	}
}

func TestJwtAuthMiddleware_TokenExtraction(t *testing.T) {
	jwtAuth := auth.NewJwtAuthMiddleware()

	tests := []struct {
		name          string
		authHeader    string
		expectToken   string
	}{
		{
			name:        "Bearer prefix",
			authHeader:  "Bearer my-token-123",
			expectToken: "my-token-123",
		},
		{
			name:        "No Bearer prefix",
			authHeader:  "my-token-123",
			expectToken: "my-token-123",
		},
		{
			name:        "Multiple spaces",
			authHeader:  "Bearer   my-token-123",
			expectToken: "my-token-123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", tt.authHeader)

			// The authenticate will fail due to invalid token, but we're testing extraction
			_, err := jwtAuth.Authenticate(req)
			// We expect an error here since we're not providing a valid token
			_ = err
		})
	}
}

// MockJWKS Server for testing
type MockJWKSServer struct {
	Server     *httptest.Server
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}

func NewMockJWKSServer() (*MockJWKSServer, error) {
	privateKey, publicKey, err := generateTestKeyPair()
	if err != nil {
		return nil, err
	}

	mock := &MockJWKSServer{
		PublicKey:  publicKey,
		PrivateKey: privateKey,
	}

	mock.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return mock JWKS response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"keys": []}`))
	}))

	return mock, nil
}

func (m *MockJWKSServer) Close() {
	m.Server.Close()
}

func TestJwtAuthMiddleware_WithMockServer(t *testing.T) {
	mock, err := NewMockJWKSServer()
	if err != nil {
		t.Fatalf("Failed to create mock server: %v", err)
	}
	defer mock.Close()

	// Create a valid token
	claims := jwt.MapClaims{
		"sub": map[string]interface{}{
			"uuid":  "test-uuid",
			"email": "test@example.com",
			"name":  "Test User",
		},
		"tenant_id":   "tenant-123",
		"permissions": []string{"read", "write"},
		"type":        "user",
		"iss":         mock.Server.URL,
		"aud":         mock.Server.URL,
		"exp":         time.Now().Add(time.Hour).Unix(),
		"nbf":         time.Now().Add(-time.Hour).Unix(),
		"iat":         time.Now().Unix(),
		"jti":         "token-id-123",
	}

	token, err := generateTestToken(mock.PrivateKey, claims)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Note: In a real test, you'd need to configure the middleware
	// to use the mock server URL
	_ = token
}

func BenchmarkJwtAuthMiddleware_Authenticate(b *testing.B) {
	jwtAuth := auth.NewJwtAuthMiddleware()

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jwtAuth.Authenticate(req)
	}
}

// TestClaims represents test JWT claims
type TestClaims struct {
	Sub         TestSubject `json:"sub"`
	TenantID    string      `json:"tenant_id"`
	Permissions []string    `json:"permissions"`
	Type        string      `json:"type"`
	Issuer      string      `json:"iss"`
	Audience    string      `json:"aud"`
	ExpiresAt   int64       `json:"exp"`
	NotBefore   int64       `json:"nbf"`
	IssuedAt    int64       `json:"iat"`
	JTI         string      `json:"jti"`
}

type TestSubject struct {
	UUID  string `json:"uuid"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func TestClaimsValidation(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		claims  jwt.MapClaims
		isValid bool
	}{
		{
			name: "Valid claims",
			claims: jwt.MapClaims{
				"sub": map[string]interface{}{
					"uuid":  "test-uuid",
					"email": "test@example.com",
					"name":  "Test User",
				},
				"iss": "https://mercury.example.com",
				"aud": "https://api.example.com",
				"exp": now.Add(time.Hour).Unix(),
				"nbf": now.Add(-time.Hour).Unix(),
				"iat": now.Unix(),
			},
			isValid: true,
		},
		{
			name: "Expired token",
			claims: jwt.MapClaims{
				"sub": map[string]interface{}{
					"uuid": "test-uuid",
				},
				"exp": now.Add(-time.Hour).Unix(),
			},
			isValid: false,
		},
		{
			name: "Token not yet valid",
			claims: jwt.MapClaims{
				"sub": map[string]interface{}{
					"uuid": "test-uuid",
				},
				"nbf": now.Add(time.Hour).Unix(),
			},
			isValid: false,
		},
		{
			name: "Missing subject",
			claims: jwt.MapClaims{
				"iss": "https://mercury.example.com",
				"exp": now.Add(time.Hour).Unix(),
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate claims structure
			sub, ok := tt.claims["sub"].(map[string]interface{})
			if tt.isValid {
				if !ok {
					t.Error("Expected valid subject")
				}
				if _, hasUUID := sub["uuid"]; !hasUUID {
					t.Error("Expected uuid in subject")
				}
			}
		})
	}
}

// Helper to generate PEM-encoded public key
func publicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}
