package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authGin "github.com/wazobiatech/auth-middleware-go/pkg/adapters/gin"
)

// TestJWTAuthenticationFlow tests complete JWT authentication flow
func TestJWTAuthenticationFlow(t *testing.T) {
	// Set up test environment
	os.Setenv("MERCURY_BASE_URL", "http://localhost:4000")
	os.Setenv("SIGNATURE_SHARED_SECRET", "test-secret")
	os.Setenv("REDIS_URL", "localhost:6379")

	// Start mock Mercury JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return mock JWKS response
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"keys": [{
				"kty": "RSA",
				"kid": "test-key-1",
				"use": "sig",
				"alg": "RS512",
				"n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				"e": "AQAB"
			}]
		}`)
	}))
	defer jwksServer.Close()

	// Test JWT authentication with Gin
	t.Run("GinJWTMiddleware", func(t *testing.T) {
		gin.SetMode(gin.TestMode)
		router := gin.New()
		router.Use(authGin.JWTMiddleware())
		router.GET("/test", func(c *gin.Context) {
			if user, exists := c.Get(authGin.AuthUserKey); exists {
				c.JSON(200, gin.H{"user": user})
			} else {
				c.JSON(500, gin.H{"error": "User not found"})
			}
		})

		// Test without token
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, 401, w.Code)

		// Test with valid token would require actual JWT from Mercury
		// This is where you would test with a real token in integration
	})
}

// TestRedisIntegration tests Redis connectivity and caching
func TestRedisIntegration(t *testing.T) {
	redisURL := os.Getenv("TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("TEST_REDIS_URL not set, skipping Redis integration test")
	}

	// Test Redis connection
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: os.Getenv("TEST_REDIS_PASSWORD"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Ping Redis
	err := redisClient.Ping(ctx).Err()
	require.NoError(t, err, "Failed to connect to Redis")

	// Test set/get
	testKey := "auth_middleware_test_key"
	testValue := "test_value_" + time.Now().Format(time.RFC3339)

	err = redisClient.Set(ctx, testKey, testValue, 10*time.Second).Err()
	require.NoError(t, err)

	value, err := redisClient.Get(ctx, testKey).Result()
	require.NoError(t, err)
	assert.Equal(t, testValue, value)

	// Clean up
	err = redisClient.Del(ctx, testKey).Err()
	require.NoError(t, err)

	t.Logf("✅ Redis integration test passed with URL: %s", redisURL)
}

// TestServiceTokenGeneration tests service token generation flow
func TestServiceTokenGeneration(t *testing.T) {
	// This requires actual Mercury service credentials
	clientID := os.Getenv("TEST_CLIENT_ID")
	clientSecret := os.Getenv("TEST_CLIENT_SECRET")
	mercuryURL := os.Getenv("TEST_MERCURY_BASE_URL")

	if clientID == "" || clientSecret == "" || mercuryURL == "" {
		t.Skip("Test credentials not set, skipping service token generation test")
	}

	// Set environment for service client
	os.Setenv("CLIENT_ID", clientID)
	os.Setenv("CLIENT_SECRET", clientSecret)
	os.Setenv("MERCURY_BASE_URL", mercuryURL)

	// Note: This would require actual Mercury service to be running
	// or a mock to be set up

	t.Log("Service token generation test would require actual Mercury service")
}
