package auth

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wazobiatech/auth-middleware-go/pkg/jwks"
	"github.com/wazobiatech/auth-middleware-go/pkg/redis"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

// JwtAuthMiddleware provides advanced JWT authentication with JWKS support
type JwtAuthMiddleware struct {
	expectedIssuer string
	jwksCache      *jwks.Cache
	redisClient    *redis.Client
}

// NewJwtAuthMiddleware creates a new JWT authentication middleware instance
func NewJwtAuthMiddleware() *JwtAuthMiddleware {
	config := utils.GetConfig()

	jwksCache := jwks.NewCache()
	redisClient := redis.NewClient()

	return &JwtAuthMiddleware{
		expectedIssuer: config.MercuryBaseURL,
		jwksCache:      jwksCache,
		redisClient:    redisClient,
	}
}

// Authenticate processes the JWT token and sets user context
func (j *JwtAuthMiddleware) Authenticate(req *http.Request) (*types.AuthUser, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		authHeader = req.Header.Get("x-project-token")
	}

	if authHeader == "" {
		return nil, &types.AuthError{
			Code:    types.ErrCodeMissingHeader,
			Message: "No authorization header provided (Authorization or x-project-token)",
		}
	}

	var token string
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		token = authHeader
	}

	if token == "" {
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "No token provided",
		}
	}

	// Get signing key from JWKS
	publicKey, err := j.getSigningKey(token)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing key: %w", err)
	}

	// Validate token
	user, err := j.validate(token, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}

	return user, nil
}

// decodeJWTTokenForTenantId extracts tenant ID from JWT token without verification
func (j *JwtAuthMiddleware) decodeJWTTokenForTenantId(rawJwtToken string) (string, error) {
	parts := strings.Split(rawJwtToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format")
	}

	// Decode payload
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		return "", fmt.Errorf("failed to unmarshal JWT payload: %w", err)
	}

	tenantID, ok := payload["tenant_id"].(string)
	if !ok {
		// Try project_uuid as fallback
		tenantID, ok = payload["project_uuid"].(string)
		if !ok {
			return "", nil // neither tenant_id nor project_uuid found
		}
	}

	return tenantID, nil
}

// getJwksUriAndPath constructs JWKS URI and path for a tenant
func (j *JwtAuthMiddleware) getJwksUriAndPath(tenantId string) (string, string) {
	config := utils.GetConfig()
	domain := config.MercuryBaseURL

	log.Printf("JWKS Debug - MERCURY_BASE_URL: %s", domain)
	log.Printf("JWKS Debug - tenantId: %s", tenantId)

	path := fmt.Sprintf("auth/projects/%s/.well-known/jwks.json", tenantId)
	uri := fmt.Sprintf("%s/%s", domain, path)

	log.Printf("JWKS Debug - Constructed URI: %s", uri)
	return uri, path
}

// getSigningKey retrieves the public key for JWT verification
func (j *JwtAuthMiddleware) getSigningKey(rawJwtToken string) (*rsa.PublicKey, error) {
	parts := strings.Split(rawJwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerData, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWT header: %w", err)
	}

	if header.Kid == "" {
		return nil, fmt.Errorf("missing key ID (kid) in token header")
	}

	tenantId, err := j.decodeJWTTokenForTenantId(rawJwtToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode tenant ID: %w", err)
	}

	uri, path := j.getJwksUriAndPath(tenantId)

	// Get or fetch JWKS
	keyStore, err := j.jwksCache.GetOrFetch(tenantId, uri, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Find the specific key
	publicKey, err := keyStore.GetPublicKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("key %s not found in JWKS for tenant %s: %w", header.Kid, tenantId, err)
	}

	return publicKey, nil
}

// createTokenCacheKey creates a cache key for validated tokens
func (j *JwtAuthMiddleware) createTokenCacheKey(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := fmt.Sprintf("%x", hash)[:32]
	return fmt.Sprintf("validated_token:%s", tokenHash)
}

// cacheValidatedToken stores validated token in Redis
func (j *JwtAuthMiddleware) cacheValidatedToken(payload *types.JwtPayload, rawToken string) error {
	cacheKey := j.createTokenCacheKey(rawToken)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	config := utils.GetConfig()
	expiry := time.Duration(config.CacheExpiryTime) * time.Second

	return j.redisClient.Set(cacheKey, string(payloadBytes), expiry)
}

// getCachedToken retrieves validated token from Redis cache
func (j *JwtAuthMiddleware) getCachedToken(rawToken string) (*types.JwtPayload, error) {
	cacheKey := j.createTokenCacheKey(rawToken)

	cachedPayload, err := j.redisClient.Get(cacheKey)
	if err != nil {
		return nil, err // Cache miss or error
	}

	var payload types.JwtPayload
	if err := json.Unmarshal([]byte(cachedPayload), &payload); err != nil {
		// Delete corrupted cache entry
		j.redisClient.Del(cacheKey)
		return nil, fmt.Errorf("failed to unmarshal cached payload: %w", err)
	}

	// Validate cached payload structure
	if payload.Sub.UUID == "" || payload.Sub.Email == "" {
		j.redisClient.Del(cacheKey)
		return nil, fmt.Errorf("invalid cached payload structure")
	}

	// Check if token is expired
	now := time.Now().Unix()
	if payload.ExpiresAt > 0 && payload.ExpiresAt < now {
		j.redisClient.Del(cacheKey)
		return nil, fmt.Errorf("cached token expired")
	}

	return &payload, nil
}

// validate performs comprehensive JWT token validation
func (j *JwtAuthMiddleware) validate(rawToken string, publicKey *rsa.PublicKey) (*types.AuthUser, error) {
	// Check cache first
	cachedPayload, err := j.getCachedToken(rawToken)
	if err == nil && cachedPayload != nil {
		return &types.AuthUser{
			UUID:        cachedPayload.Sub.UUID,
			Email:       cachedPayload.Sub.Email,
			Name:        cachedPayload.Sub.Name,
			TenantID:    cachedPayload.TenantID,
			Permissions: cachedPayload.Permissions,
			TokenID:     cachedPayload.JTI,
		}, nil
	}

	// Parse and verify the token.
	// Allow 10 seconds of clock skew between services.
	parser := jwt.NewParser(jwt.WithLeeway(10 * time.Second))
	token, err := parser.Parse(rawToken, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		log.Printf("Token validation failed: %v", err)
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok || iss != j.expectedIssuer {
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidIssuer,
			Message: fmt.Sprintf("invalid issuer. Expected: %s, Got: %s", j.expectedIssuer, iss),
		}
	}

	// Validate timestamps
	now := time.Now().Unix()
	if exp, ok := claims["exp"].(float64); ok && int64(exp) < now {
		return nil, &types.AuthError{
			Code:    types.ErrCodeExpiredToken,
			Message: "token expired",
		}
	}

	if nbf, ok := claims["nbf"].(float64); ok && int64(nbf) > now {
		return nil, &types.AuthError{
			Code:    types.ErrCodeExpiredToken,
			Message: "token not yet valid",
		}
	}

	// Check for token revocation
	if jti, ok := claims["jti"].(string); ok && jti != "" {
		revocationKey := fmt.Sprintf("revoked_token:%s", jti)
		isRevoked, err := j.redisClient.Exists(revocationKey)
		if err != nil {
			return nil, fmt.Errorf("redis error checking revocation: %w", err)
		}
		if isRevoked {
			return nil, &types.AuthError{
				Code:    types.ErrCodeRevokedToken,
				Message: "token has been revoked",
			}
		}
	}

	// Extract user information from 'sub' claim
	sub, ok := claims["sub"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid or missing 'sub' claim")
	}

	uuid, _ := sub["uuid"].(string)
	email, _ := sub["email"].(string)
	name, _ := sub["name"].(string)

	if uuid == "" {
		return nil, fmt.Errorf("invalid JWT payload structure: missing user UUID")
	}

	tenantID := getStringClaim(claims, "tenant_id")
	if tenantID == "" {
		tenantID = getStringClaim(claims, "project_uuid")
	}

	// Create payload for caching
	payload := &types.JwtPayload{
		Sub: struct {
			UUID  string `json:"uuid"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}{
			UUID:  uuid,
			Email: email,
			Name:  name,
		},
		TenantID:    tenantID,
		ProjectUUID: getStringClaim(claims, "project_uuid"),
		Permissions: getStringArrayClaim(claims, "permissions"),
		Type:        getStringClaim(claims, "type"),
		Issuer:      iss,
		Audience:    getStringClaim(claims, "aud"),
		ExpiresAt:   int64(claims["exp"].(float64)),
		NotBefore:   int64(getFloatClaim(claims, "nbf")),
		IssuedAt:    int64(getFloatClaim(claims, "iat")),
		JTI:         getStringClaim(claims, "jti"),
	}

	// Cache the validated token
	if err := j.cacheValidatedToken(payload, rawToken); err != nil {
		log.Printf("Warning: failed to cache validated token: %v", err)
	}

	authUser := &types.AuthUser{
		UUID:        uuid,
		Email:       email,
		Name:        name,
		TenantID:    payload.TenantID,
		Permissions: payload.Permissions,
		TokenID:     payload.JTI,
	}

	return authUser, nil
}

// Helper functions to safely extract claims
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getFloatClaim(claims jwt.MapClaims, key string) float64 {
	if val, ok := claims[key].(float64); ok {
		return val
	}
	return 0
}

func getStringArrayClaim(claims jwt.MapClaims, key string) []string {
	if arr, ok := claims[key].([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return []string{}
}
