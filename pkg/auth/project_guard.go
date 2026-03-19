package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/wazobiatech/auth-middleware-go/pkg/client"
	"github.com/wazobiatech/auth-middleware-go/pkg/jwks"
	"github.com/wazobiatech/auth-middleware-go/pkg/redis"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

// ProjectAuthMiddleware provides Redis-cached JWKS authentication for platform, project & service tokens
type ProjectAuthMiddleware struct {
	serviceJwksCacheKey string
	jwksCacheTTL        time.Duration
	serviceName         string
	jwksCache           *jwks.Cache
	redisClient         *redis.Client
	serviceClient       *client.ServiceClient
}

// NewProjectAuthMiddleware creates a new project authentication middleware
func NewProjectAuthMiddleware(serviceName string) *ProjectAuthMiddleware {
	return &ProjectAuthMiddleware{
		serviceJwksCacheKey: "service_jwks_cache",
		jwksCacheTTL:        5 * time.Hour, // 5 hours
		serviceName:         strings.ToLower(serviceName),
		jwksCache:           jwks.NewCache(),
		redisClient:         redis.NewClient(),
		serviceClient:       client.NewServiceClient(),
	}
}

// TokenValidationResult represents the result of token validation
type TokenValidationResult struct {
	IsValid bool
	Payload interface{}
	Error   string
}

// Authenticate processes platform, project, or service tokens
func (p *ProjectAuthMiddleware) Authenticate(req *http.Request) (*types.AuthenticatedRequest, error) {
	// Extract token from x-project-token header
	authHeader := req.Header.Get("x-project-token")
	if authHeader == "" {
		return nil, &types.AuthError{
			Code:    types.ErrCodeMissingHeader,
			Message: "No token provided, required_header: 'x-project-token'",
		}
	}

	// Handle Bearer prefix
	var token string
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		token = authHeader
	}

	if token == "" {
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: "Empty token",
		}
	}

	// Validate token using cached JWKS
	validation, err := p.validateToken(token)
	if err != nil {
		return nil, fmt.Errorf("token validation error: %w", err)
	}

	if !validation.IsValid {
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: fmt.Sprintf("Invalid token: %s", validation.Error),
		}
	}

	// Route based on token type
	authReq := &types.AuthenticatedRequest{}

	switch payload := validation.Payload.(type) {
	case *types.PlatformTokenPayload:
		p.injectPlatformContext(authReq, payload)
	case *types.ProjectTokenPayload:
		if err := p.injectProjectContext(authReq, payload); err != nil {
			return nil, fmt.Errorf("failed to inject project context: %w", err)
		}
	case *types.ServiceTokenPayload:
		p.injectServiceContext(authReq, payload)
	default:
		return nil, &types.AuthError{
			Code:    types.ErrCodeInvalidToken,
			Message: fmt.Sprintf("Invalid token type: %T", payload),
		}
	}

	return authReq, nil
}

// injectPlatformContext adds platform token context to the request
func (p *ProjectAuthMiddleware) injectPlatformContext(req *types.AuthenticatedRequest, payload *types.PlatformTokenPayload) {
	req.Platform = &types.PlatformContext{
		TenantID:    payload.TenantID,
		ProjectUUID: payload.TenantID,
		Scopes:      payload.Scopes,
		TokenID:     payload.TokenID,
		ExpiresAt:   time.Unix(payload.ExpiresAt, 0),
	}
}

// injectProjectContext adds project token context to the request
func (p *ProjectAuthMiddleware) injectProjectContext(req *types.AuthenticatedRequest, payload *types.ProjectTokenPayload) error {
	logger := utils.NewLogger("project-auth")

	logger.Info("Injecting project context", map[string]interface{}{
		"tenant_id":        payload.TenantID,
		"token_id":         payload.TokenID,
		"enabled_services": payload.EnabledServices,
	})

	// Generate access token for service validation
	accessToken, err := p.serviceClient.GenerateToken()
	if err != nil {
		logger.Error("Failed to generate access token", map[string]interface{}{
			"tenant_id": payload.TenantID,
			"token_id":  payload.TokenID,
			"error":     err.Error(),
		})
		return fmt.Errorf("failed to generate access token: %w", err)
	}

	logger.Info("Access token generated", map[string]interface{}{
		"access_token_prefix": accessToken[:min(20, len(accessToken))],
	})

	// Get service ID from Mercury
	serviceID, err := p.serviceClient.GetServiceByID(accessToken)
	if err != nil {
		logger.Error("Failed to retrieve service ID from Mercury", map[string]interface{}{
			"tenant_id": payload.TenantID,
			"token_id":  payload.TokenID,
			"error":     err.Error(),
		})
		return fmt.Errorf("failed to retrieve service ID: %w", err)
	}

	logger.Info("Service UUID found", map[string]interface{}{"service_id": serviceID})

	// Check if service is enabled
	serviceEnabled := false
	for _, enabled := range payload.EnabledServices {
		if enabled == serviceID {
			serviceEnabled = true
			break
		}
	}

	if !serviceEnabled {
		logger.Error("Service access denied", map[string]interface{}{
			"tenant_id":        payload.TenantID,
			"token_id":         payload.TokenID,
			"service_id":       serviceID,
			"enabled_services": payload.EnabledServices,
		})
		return &types.AuthError{
			Code: types.ErrCodeInsufficientScope,
			Message: fmt.Sprintf("Service access denied. Service '%s' is not enabled for this project. Enabled services: %s",
				serviceID, strings.Join(payload.EnabledServices, ", ")),
		}
	}

	logger.Info("Service is enabled for this project", map[string]interface{}{
		"enabled_services": payload.EnabledServices,
		"service_id":       serviceID,
	})

	req.Project = &types.ProjectContext{
		TenantID:        payload.TenantID,
		ProjectUUID:     payload.TenantID,
		EnabledServices: payload.EnabledServices,
		Scopes:          payload.Scopes,
		SecretVersion:   payload.SecretVersion,
		TokenID:         payload.TokenID,
		ExpiresAt:       time.Unix(payload.ExpiresAt, 0),
	}

	logger.Info("Project context injected successfully", map[string]interface{}{
		"tenant_id":  payload.TenantID,
		"token_id":   payload.TokenID,
		"service_id": serviceID,
		"scopes":     req.Project.Scopes,
	})

	return nil
}

// injectServiceContext adds service token context to the request
func (p *ProjectAuthMiddleware) injectServiceContext(req *types.AuthenticatedRequest, payload *types.ServiceTokenPayload) {
	// Parse scopes from space-separated string
	scopes := []string{}
	if payload.Scope != "" {
		scopes = strings.Fields(payload.Scope)
	}

	req.Service = &types.ServiceContext{
		ClientID:    payload.ClientID,
		ServiceName: payload.ServiceName,
		Scopes:      scopes,
		TokenID:     payload.JTI,
		IssuedAt:    time.Unix(payload.IssuedAt, 0),
		ExpiresAt:   time.Unix(payload.ExpiresAt, 0),
	}

	logger := utils.NewLogger("service-auth")
	logger.Info("Service authenticated", map[string]interface{}{
		"service_name": payload.ServiceName,
		"scopes":       scopes,
	})
}

// validateToken validates and parses the JWT token
func (p *ProjectAuthMiddleware) validateToken(token string) (*TokenValidationResult, error) {
	// Get public key from cached JWKS
	publicKey, err := p.getPublicKeyFromCache(token)
	if err != nil {
		return &TokenValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("failed to get public key: %v", err),
		}, nil
	}

	// Verify JWT with RSA public key
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return &TokenValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("JWT verification failed: %v", err),
		}, nil
	}

	if !parsedToken.Valid {
		return &TokenValidationResult{
			IsValid: false,
			Error:   "invalid token payload",
		}, nil
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return &TokenValidationResult{
			IsValid: false,
			Error:   "invalid token claims",
		}, nil
	}

	tokenType, ok := claims["type"].(string)
	if !ok {
		return &TokenValidationResult{
			IsValid: false,
			Error:   "missing or invalid token type",
		}, nil
	}

	// Validate based on token type
	switch tokenType {
	case "platform":
		return p.validatePlatformToken(claims)
	case "project":
		return p.validateProjectToken(claims)
	case "service":
		return p.validateServiceToken(claims)
	default:
		return &TokenValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("unsupported token type: %s", tokenType),
		}, nil
	}
}

// validateProjectToken validates project token structure, secret version, and revocation
func (p *ProjectAuthMiddleware) validateProjectToken(claims jwt.MapClaims) (*TokenValidationResult, error) {
	// Validate structure
	tenantID, ok1 := claims["tenant_id"].(string)
	if !ok1 || tenantID == "" {
		tenantID, ok1 = claims["project_uuid"].(string)
	}
	tokenID, ok2 := claims["token_id"].(string)

	if !ok1 || !ok2 || tenantID == "" || tokenID == "" {
		return &TokenValidationResult{
			IsValid: false,
			Error:   "invalid project token structure",
		}, nil
	}

	enabledServices := getStringArrayClaim(claims, "enabled_services")

	// Check secret version
	secretVersion := int(getFloatClaim(claims, "secret_version"))
	currentSecretVersion, err := p.getCurrentSecretVersion(tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current secret version: %w", err)
	}

	if currentSecretVersion > 0 && secretVersion < currentSecretVersion {
		return &TokenValidationResult{
			IsValid: false,
			Error:   fmt.Sprintf("token secret version outdated (token: %d, current: %d) - re-authentication required", secretVersion, currentSecretVersion),
		}, nil
	}

	// Check if token is revoked (only if Redis is connected)
	if p.redisClient.IsConnected() {
		exists, err := p.redisClient.Exists(fmt.Sprintf("project_token:%s", tokenID))
		if err != nil {
			log.Printf("Warning: Redis error checking revocation: %v", err)
		} else if !exists {
			return &TokenValidationResult{
				IsValid: false,
				Error:   "token has been revoked",
			}, nil
		}
	}

	// Create payload
	payload := &types.ProjectTokenPayload{
		TenantID:        tenantID,
		SecretVersion:   secretVersion,
		EnabledServices: enabledServices,
		TokenID:         tokenID,
		Type:            "project",
		Scopes:          getStringArrayClaim(claims, "scopes"),
		IssuedAt:        int64(getFloatClaim(claims, "iat")),
		NotBefore:       int64(getFloatClaim(claims, "nbf")),
		ExpiresAt:       int64(getFloatClaim(claims, "exp")),
		Issuer:          getStringClaim(claims, "iss"),
		Audience:        getStringClaim(claims, "aud"),
	}

	return &TokenValidationResult{
		IsValid: true,
		Payload: payload,
	}, nil
}

// validateServiceToken validates service token structure (stateless - no revocation check)
func (p *ProjectAuthMiddleware) validateServiceToken(claims jwt.MapClaims) (*TokenValidationResult, error) {
	// Validate structure
	clientID, ok1 := claims["client_id"].(string)
	serviceName, ok2 := claims["service_name"].(string)
	jti, ok3 := claims["jti"].(string)

	if !ok1 || !ok2 || !ok3 || clientID == "" || serviceName == "" || jti == "" {
		return &TokenValidationResult{
			IsValid: false,
			Error:   "invalid service token structure",
		}, nil
	}

	// Service tokens are stateless - no Redis revocation check
	// Only signature + expiration validation (done by jwt.Parse)

	payload := &types.ServiceTokenPayload{
		Type:        "service",
		ClientID:    clientID,
		ServiceName: serviceName,
		Scope:       getStringClaim(claims, "scope"),
		JTI:         jti,
		IssuedAt:    int64(getFloatClaim(claims, "iat")),
		NotBefore:   int64(getFloatClaim(claims, "nbf")),
		ExpiresAt:   int64(getFloatClaim(claims, "exp")),
		Issuer:      getStringClaim(claims, "iss"),
		Audience:    getStringClaim(claims, "aud"),
	}

	return &TokenValidationResult{
		IsValid: true,
		Payload: payload,
	}, nil
}

// validatePlatformToken validates platform token structure
func (p *ProjectAuthMiddleware) validatePlatformToken(claims jwt.MapClaims) (*TokenValidationResult, error) {
	// Validate structure
	tenantID, ok1 := claims["tenant_id"].(string)
	if !ok1 || tenantID == "" {
		tenantID, ok1 = claims["project_uuid"].(string)
	}
	tokenID, ok2 := claims["token_id"].(string)

	if !ok1 || !ok2 || tenantID == "" || tokenID == "" {
		return &TokenValidationResult{
			IsValid: false,
			Error:   "invalid platform token structure",
		}, nil
	}

	// Check secret version (optional for platform tokens)
	secretVersion := int(getFloatClaim(claims, "secret_version"))

	payload := &types.PlatformTokenPayload{
		TenantID:      tenantID,
		SecretVersion: secretVersion,
		TokenID:       tokenID,
		Type:          "platform",
		Scopes:        getStringArrayClaim(claims, "scopes"),
		IssuedAt:      int64(getFloatClaim(claims, "iat")),
		NotBefore:     int64(getFloatClaim(claims, "nbf")),
		ExpiresAt:     int64(getFloatClaim(claims, "exp")),
		Issuer:        getStringClaim(claims, "iss"),
		Audience:      getStringClaim(claims, "aud"),
	}

	return &TokenValidationResult{
		IsValid: true,
		Payload: payload,
	}, nil
}

// getPublicKeyFromCache retrieves RSA public key from cached JWKS with auto-refresh on key miss
func (p *ProjectAuthMiddleware) getPublicKeyFromCache(token string) (interface{}, error) {
	// Extract kid from JWT header
	header, err := p.decodeJwtHeader(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	if header.Kid == "" {
		return nil, fmt.Errorf("missing key ID in token header")
	}

	// Extract payload to determine token type
	payload, err := p.decodeJwtPayload(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Determine JWKS endpoint and cache key based on token type
	var cacheKey, jwksPath string
	var jwksUri string

	if payload["type"] == "service" {
		cacheKey = p.serviceJwksCacheKey
		jwksPath = "auth/service/.well-known/jwks.json"
		fmt.Println("Service token detected, using service JWKS endpoint")
	} else {
		// Cache per tenant - each tenant gets its own cache
		tenantID, ok := payload["tenant_id"].(string)
		if !ok || tenantID == "" {
			tenantID, ok = payload["project_uuid"].(string)
		}
		if !ok || tenantID == "" {
			return nil, fmt.Errorf("missing tenant_id or project_uuid in token payload")
		}
		cacheKey = fmt.Sprintf("jwks_cache:%s", tenantID)
		jwksPath = fmt.Sprintf("auth/projects/%s/.well-known/jwks.json", tenantID)
		fmt.Printf("%s token detected, tenant_id: %s\n", payload["type"], tenantID)
	}

	config := utils.GetConfig()
	jwksUri = fmt.Sprintf("%s/%s", config.MercuryBaseURL, jwksPath)

	// Get or fetch JWKS from cache
	keyStore, err := p.jwksCache.GetOrFetch(cacheKey, jwksUri, jwksPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWKS: %w", err)
	}

	// Get the public key
	publicKey, err := keyStore.GetPublicKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("key %s not found in JWKS: %w", header.Kid, err)
	}

	return publicKey, nil
}

// decodeJwtHeader decodes JWT header to extract kid
func (p *ProjectAuthMiddleware) decodeJwtHeader(token string) (*struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	return &header, nil
}

// decodeJwtPayload decodes JWT payload to extract tenant_id and type (without verification)
func (p *ProjectAuthMiddleware) decodeJwtPayload(token string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
	}

	return payload, nil
}

// getCurrentSecretVersion gets current secret version from Redis (cached by Mercury)
func (p *ProjectAuthMiddleware) getCurrentSecretVersion(tenantID string) (int, error) {
	cacheKey := fmt.Sprintf("tenant_secret_version:%s", tenantID)

	cachedVersion, err := p.redisClient.Get(cacheKey)
	if err != nil {
		// If key doesn't exist, return 0 to allow validation
		return 0, nil
	}

	version, err := strconv.Atoi(cachedVersion)
	if err != nil {
		return 0, fmt.Errorf("invalid version format: %w", err)
	}

	return version, nil
}

// SetCacheTTL updates JWKS cache TTL (can be increased beyond 5 hours)
func (p *ProjectAuthMiddleware) SetCacheTTL(duration time.Duration) {
	p.jwksCacheTTL = duration
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
