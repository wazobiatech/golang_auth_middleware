package types

import (
	"time"

	"github.com/gin-gonic/gin"
)

// ==================== REQUEST TYPES ====================

// AuthenticatedRequest extends standard HTTP request with authentication context
type AuthenticatedRequest struct {
	Platform *PlatformContext `json:"platform,omitempty"`
	Project  *ProjectContext  `json:"project,omitempty"`
	Service  *ServiceContext  `json:"service,omitempty"`
	User     *AuthUser        `json:"user,omitempty"`
}

// GinContext wraps Gin context for GraphQL integration
type GinContext struct {
	Context *gin.Context
}

// ==================== TOKEN PAYLOAD TYPES ====================

// PlatformTokenPayload represents platform-level access tokens
type PlatformTokenPayload struct {
	TenantID      string   `json:"tenant_id"`
	SecretVersion int      `json:"secret_version"`
	TokenID       string   `json:"token_id"`
	Type          string   `json:"type"` // "platform"
	Scopes        []string `json:"scopes"`
	IssuedAt      int64    `json:"iat"`
	NotBefore     int64    `json:"nbf"`
	ExpiresAt     int64    `json:"exp"`
	Issuer        string   `json:"iss"` // mercury.{domain}.com
	Audience      string   `json:"aud"` // mercury.{domain}.com (platform tokens only work with Mercury)
}

// ProjectTokenPayload represents project-level access tokens
type ProjectTokenPayload struct {
	TenantID        string   `json:"tenant_id"`
	SecretVersion   int      `json:"secret_version"`
	EnabledServices []string `json:"enabled_services"`
	TokenID         string   `json:"token_id"`
	Type            string   `json:"type"` // "project"
	Scopes          []string `json:"scopes"`
	IssuedAt        int64    `json:"iat"`
	NotBefore       int64    `json:"nbf"`
	ExpiresAt       int64    `json:"exp"`
	Issuer          string   `json:"iss"` // mercury.{domain}.com
	Audience        string   `json:"aud"` // *.{domain}.com (any enabled service)
}

// UserTokenPayload represents user access tokens
type UserTokenPayload struct {
	UserID    string   `json:"user_id"`
	TenantID  string   `json:"tenant_id"`
	TokenID   string   `json:"token_id"`
	Type      string   `json:"type"` // "user"
	Scopes    []string `json:"scopes"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	ExpiresAt int64    `json:"exp"`
	Issuer    string   `json:"iss"`           // mercury.{domain}.com
	Audience  string   `json:"aud"`           // *.{domain}.com
	JTI       string   `json:"jti,omitempty"` // JWT ID for revocation tracking
}

// ServiceTokenPayload represents service-to-service tokens
type ServiceTokenPayload struct {
	Type        string `json:"type"` // "service"
	ClientID    string `json:"client_id"`
	ServiceName string `json:"service_name"`
	Scope       string `json:"scope"` // space-separated scopes
	JTI         string `json:"jti"`   // JWT ID
	IssuedAt    int64  `json:"iat"`
	NotBefore   int64  `json:"nbf"`
	ExpiresAt   int64  `json:"exp"`
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
}

// ==================== CONTEXT TYPES ====================

// PlatformContext contains platform authentication context
type PlatformContext struct {
	TenantID    string    `json:"tenant_id"`
	ProjectUUID string    `json:"project_uuid"`
	Scopes      []string  `json:"scopes"`
	TokenID     string    `json:"token_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ProjectContext contains project authentication context
type ProjectContext struct {
	TenantID        string    `json:"tenant_id"`
	ProjectUUID     string    `json:"project_uuid"`
	EnabledServices []string  `json:"enabled_services"`
	Scopes          []string  `json:"scopes"`
	SecretVersion   int       `json:"secret_version"`
	TokenID         string    `json:"token_id"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// ServiceContext contains service authentication context
type ServiceContext struct {
	ClientID    string    `json:"client_id"`
	ServiceName string    `json:"service_name"`
	Scopes      []string  `json:"scopes"`
	TokenID     string    `json:"token_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// ==================== LEGACY/DEPRECATED TYPES ====================
// Keep these for backward compatibility, but they should be phased out

// JwtPayload represents the deprecated JWT payload structure
// Deprecated: Use PlatformTokenPayload, ProjectTokenPayload, UserTokenPayload, or ServiceTokenPayload instead
type JwtPayload struct {
	Sub struct {
		UUID  string `json:"uuid"`
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"sub,omitempty"`
	ProjectUUID string   `json:"project_uuid,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
	TenantID    string   `json:"tenant_id,omitempty"`
	Type        string   `json:"type"`
	Issuer      string   `json:"iss"`
	Audience    string   `json:"aud"`
	ExpiresAt   int64    `json:"exp"`
	NotBefore   int64    `json:"nbf"`
	IssuedAt    int64    `json:"iat"`
	JTI         string   `json:"jti,omitempty"`
}

// AuthUser represents authenticated user information
type AuthUser struct {
	UUID  string `json:"uuid"`
	Email string `json:"email"`
	Name  string `json:"name"`

	TenantID    string   `json:"tenant_id,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Role        string   `json:"role,omitempty"`
	TokenID     string   `json:"token_id,omitempty"`
	TokenType   string   `json:"token_type,omitempty"`
}

// ==================== ERROR TYPES ====================

// AuthError represents authentication-related errors
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *AuthError) Error() string {
	return e.Message
}

// Common error codes
const (
	ErrCodeInvalidToken      = "INVALID_TOKEN"
	ErrCodeExpiredToken      = "EXPIRED_TOKEN"
	ErrCodeRevokedToken      = "REVOKED_TOKEN"
	ErrCodeInsufficientScope = "INSUFFICIENT_SCOPE"
	ErrCodeMissingHeader     = "MISSING_HEADER"
	ErrCodeInvalidIssuer     = "INVALID_ISSUER"
	ErrCodeInvalidAudience   = "INVALID_AUDIENCE"
	ErrCodeJWKSFetchError    = "JWKS_FETCH_ERROR"
	ErrCodeRedisError        = "REDIS_ERROR"
)
