// Package authgo provides comprehensive JWT authentication middleware for Go microservices
// It supports multiple token types (platform, project, user, service), JWKS validation,
// Redis caching, and integrations with popular Go web frameworks.
package authgo

import (
	"github.com/wazobiatech/golang_auth_middleware/pkg/auth"
	"github.com/wazobiatech/golang_auth_middleware/pkg/types"
	"github.com/wazobiatech/golang_auth_middleware/pkg/utils"
	
	// Framework adapters
	"github.com/wazobiatech/golang_auth_middleware/pkg/adapters/gin"
	
	// Core packages - re-exported for convenience
	"github.com/wazobiatech/golang_auth_middleware/pkg/client"
	"github.com/wazobiatech/golang_auth_middleware/pkg/jwks"
	"github.com/wazobiatech/golang_auth_middleware/pkg/redis"
)

// Re-export core types for easier importing
type (
	// Authentication types
	AuthUser              = types.AuthUser
	AuthenticatedRequest  = types.AuthenticatedRequest
	PlatformContext       = types.PlatformContext
	ProjectContext        = types.ProjectContext
	ServiceContext        = types.ServiceContext
	AuthError             = types.AuthError

	// Token payload types
	PlatformTokenPayload  = types.PlatformTokenPayload
	ProjectTokenPayload   = types.ProjectTokenPayload
	UserTokenPayload      = types.UserTokenPayload
	ServiceTokenPayload   = types.ServiceTokenPayload
	JwtPayload           = types.JwtPayload // Deprecated

	// Core middleware
	JwtAuthMiddleware     = auth.JwtAuthMiddleware
	ProjectAuthMiddleware = auth.ProjectAuthMiddleware

	// Clients and utilities
	ServiceClient         = client.ServiceClient
	RedisClient           = redis.Client
	JWKSCache            = jwks.Cache
	Config               = utils.Config
)

// Error constants - re-exported for convenience
const (
	ErrCodeInvalidToken      = types.ErrCodeInvalidToken
	ErrCodeExpiredToken      = types.ErrCodeExpiredToken
	ErrCodeRevokedToken      = types.ErrCodeRevokedToken
	ErrCodeInsufficientScope = types.ErrCodeInsufficientScope
	ErrCodeMissingHeader     = types.ErrCodeMissingHeader
	ErrCodeInvalidIssuer     = types.ErrCodeInvalidIssuer
	ErrCodeInvalidAudience   = types.ErrCodeInvalidAudience
	ErrCodeJWKSFetchError    = types.ErrCodeJWKSFetchError
	ErrCodeRedisError        = types.ErrCodeRedisError
)

// Core authentication functions - convenience wrappers

// NewJwtAuthMiddleware creates a new JWT authentication middleware
func NewJwtAuthMiddleware() *JwtAuthMiddleware {
	return auth.NewJwtAuthMiddleware()
}

// NewProjectAuthMiddleware creates a new project authentication middleware
func NewProjectAuthMiddleware(serviceName string) *ProjectAuthMiddleware {
	return auth.NewProjectAuthMiddleware(serviceName)
}

// NewServiceClient creates a new service client for Mercury API communication
func NewServiceClient() *ServiceClient {
	return client.NewServiceClient()
}

// NewRedisClient creates a new Redis client
func NewRedisClient() *RedisClient {
	return redis.NewClient()
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache() *JWKSCache {
	return jwks.NewCache()
}

// Configuration functions

// GetConfig returns the current configuration
func GetConfig() *Config {
	return utils.GetConfig()
}

// UpdateConfig updates configuration at runtime
func UpdateConfig(updates map[string]interface{}) {
	utils.UpdateConfig(updates)
}

// PrintConfig prints the current configuration (masking secrets)
func PrintConfig() {
	utils.PrintConfig()
}

// Logging functions

// NewLogger creates a new structured logger
func NewLogger(service string) *utils.Logger {
	return utils.NewLogger(service)
}

// Framework-specific middleware exports

// Gin middleware
var (
	// GinJWTMiddleware is the Gin JWT middleware
	GinJWTMiddleware = gin.JWTMiddleware
	
	// GinProjectMiddleware is the Gin project middleware
	GinProjectMiddleware = gin.ProjectMiddleware
	
	// GinRequireScope is the Gin scope validation middleware
	GinRequireScope = gin.RequireScope
	
	// GinOptionalJWTMiddleware is the optional Gin JWT middleware
	GinOptionalJWTMiddleware = gin.OptionalJWTMiddleware
	
	// GinOptionalProjectMiddleware is the optional Gin project middleware
	GinOptionalProjectMiddleware = gin.OptionalProjectMiddleware
	
	// Gin context helpers
	GinGetAuthUser              = gin.GetAuthUser
	GinGetPlatformContext       = gin.GetPlatformContext
	GinGetProjectContext        = gin.GetProjectContext
	GinGetServiceContext        = gin.GetServiceContext
	GinGetAuthenticatedRequest  = gin.GetAuthenticatedRequest
	GinMustGetAuthUser          = gin.MustGetAuthUser
	GinMustGetProjectContext    = gin.MustGetProjectContext
)

// Package information
const (
	Version = "1.0.0"
	Name    = "@wazobiatech/auth-middleware-go"
)

// GetVersion returns the package version
func GetVersion() string {
	return Version
}

// GetPackageName returns the package name
func GetPackageName() string {
	return Name
}