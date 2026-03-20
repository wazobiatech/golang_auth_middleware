package middleware

import (
	"net/http"

	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// ProjectAuthMiddleware is an alias for auth.ProjectAuthMiddleware for backward compatibility
type ProjectAuthMiddleware = auth.ProjectAuthMiddleware

// JwtAuthMiddleware is an alias for auth.JwtAuthMiddleware for backward compatibility
type JwtAuthMiddleware = auth.JwtAuthMiddleware

// NewProjectAuthMiddleware creates a new project authentication middleware
func NewProjectAuthMiddleware(serviceName string) *auth.ProjectAuthMiddleware {
	return auth.NewProjectAuthMiddleware(serviceName)
}

// NewJwtAuthMiddleware creates a new JWT authentication middleware
func NewJwtAuthMiddleware() *auth.JwtAuthMiddleware {
	return auth.NewJwtAuthMiddleware()
}

// AuthenticateUser authenticates a user request
func AuthenticateUser(r *http.Request) (*types.AuthUser, error) {
	jwtAuth := auth.NewJwtAuthMiddleware()
	return jwtAuth.Authenticate(r)
}

// AuthenticateProject authenticates a project/platform/service request
func AuthenticateProject(r *http.Request, serviceName string) (*types.AuthenticatedRequest, error) {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	return projectAuth.Authenticate(r)
}

// RequireAuth is a helper that requires authentication and returns the auth context
func RequireAuth(r *http.Request, serviceName string) (*types.AuthenticatedRequest, *types.AuthUser, error) {
	// Try project auth first
	authReq, err := AuthenticateProject(r, serviceName)
	if err == nil {
		return authReq, nil, nil
	}

	// Fall back to user auth
	user, err := AuthenticateUser(r)
	if err == nil {
		return &types.AuthenticatedRequest{User: user}, user, nil
	}

	return nil, nil, types.NewAuthError(types.ErrCodeInvalidToken, "authentication failed")
}
