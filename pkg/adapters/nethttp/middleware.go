package nethttp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

// Context keys for storing auth data
type contextKey string

const (
	authUserKey    contextKey = "auth_user"
	authRequestKey contextKey = "auth_request"
	platformKey    contextKey = "platform"
	projectKey     contextKey = "project"
	serviceKey     contextKey = "service"
)

// JWTMiddleware wraps an http.Handler with JWT authentication
func JWTMiddleware(next http.Handler) http.Handler {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("nethttp-jwt-middleware")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := jwtAuth.Authenticate(r)
		if err != nil {
			logger.Error("JWT authentication failed", map[string]interface{}{
				"error": err.Error(),
				"path":  r.URL.Path,
			})
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		// Store user in context
		ctx := context.WithValue(r.Context(), authUserKey, user)
		logger.Debug("JWT authentication successful", map[string]interface{}{
			"user_id": user.UUID,
			"email":   user.Email,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ProjectMiddleware wraps an http.Handler with project/platform/service token authentication
func ProjectMiddleware(serviceName string) func(http.Handler) http.Handler {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("nethttp-project-middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authReq, err := projectAuth.Authenticate(r)
			if err != nil {
				logger.Error("Project authentication failed", map[string]interface{}{
					"error":        err.Error(),
					"path":         r.URL.Path,
					"service_name": serviceName,
				})
				writeError(w, http.StatusUnauthorized, err.Error())
				return
			}

			// Store authentication context
			ctx := r.Context()
			ctx = context.WithValue(ctx, authRequestKey, authReq)

			if authReq.Platform != nil {
				ctx = context.WithValue(ctx, platformKey, authReq.Platform)
				logger.Debug("Platform authentication successful", map[string]interface{}{
					"tenant_id": authReq.Platform.TenantID,
					"token_id":  authReq.Platform.TokenID,
				})
			}

			if authReq.Project != nil {
				ctx = context.WithValue(ctx, projectKey, authReq.Project)
				logger.Debug("Project authentication successful", map[string]interface{}{
					"tenant_id":        authReq.Project.TenantID,
					"token_id":         authReq.Project.TokenID,
					"enabled_services": authReq.Project.EnabledServices,
				})
			}

			if authReq.Service != nil {
				ctx = context.WithValue(ctx, serviceKey, authReq.Service)
				logger.Debug("Service authentication successful", map[string]interface{}{
					"client_id":    authReq.Service.ClientID,
					"service_name": authReq.Service.ServiceName,
				})
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns a middleware that checks for specific scopes
func RequireScope(requiredScopes ...string) func(http.Handler) http.Handler {
	logger := utils.NewLogger("nethttp-scope-middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(requiredScopes) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			var scopes []string
			ctx := r.Context()

			// Try to get scopes from different auth contexts
			if authReq, ok := ctx.Value(authRequestKey).(*types.AuthenticatedRequest); ok && authReq != nil {
				if authReq.Platform != nil {
					scopes = authReq.Platform.Scopes
				} else if authReq.Project != nil {
					scopes = authReq.Project.Scopes
				} else if authReq.Service != nil {
					scopes = authReq.Service.Scopes
				}
			}

			// Check if user has all required scopes
			for _, required := range requiredScopes {
				hasScope := false
				for _, scope := range scopes {
					if scope == required {
						hasScope = true
						break
					}
				}

				if !hasScope {
					logger.Warn("Insufficient scopes", map[string]interface{}{
						"required_scopes": requiredScopes,
						"user_scopes":     scopes,
						"missing_scope":   required,
					})

					writeScopeError(w, requiredScopes, scopes)
					return
				}
			}

			logger.Debug("Scope validation passed", map[string]interface{}{
				"required_scopes": requiredScopes,
				"user_scopes":     scopes,
			})

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalJWTMiddleware provides JWT authentication but doesn't require it
func OptionalJWTMiddleware(next http.Handler) http.Handler {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("nethttp-optional-jwt-middleware")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := jwtAuth.Authenticate(r)
		if err != nil {
			logger.Debug("Optional JWT authentication failed", map[string]interface{}{
				"error": err.Error(),
				"path":  r.URL.Path,
			})
			// Continue without authentication
			next.ServeHTTP(w, r)
			return
		}

		// Store user in context if authentication succeeded
		ctx := context.WithValue(r.Context(), authUserKey, user)
		logger.Debug("Optional JWT authentication successful", map[string]interface{}{
			"user_id": user.UUID,
			"email":   user.Email,
		})

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalProjectMiddleware provides project authentication but doesn't require it
func OptionalProjectMiddleware(serviceName string) func(http.Handler) http.Handler {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("nethttp-optional-project-middleware")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authReq, err := projectAuth.Authenticate(r)
			if err != nil {
				logger.Debug("Optional project authentication failed", map[string]interface{}{
					"error":        err.Error(),
					"path":         r.URL.Path,
					"service_name": serviceName,
				})
				// Continue without project authentication
				next.ServeHTTP(w, r)
				return
			}

			// Store authentication context if successful
			ctx := r.Context()
			ctx = context.WithValue(ctx, authRequestKey, authReq)

			if authReq.Platform != nil {
				ctx = context.WithValue(ctx, platformKey, authReq.Platform)
			}
			if authReq.Project != nil {
				ctx = context.WithValue(ctx, projectKey, authReq.Project)
			}
			if authReq.Service != nil {
				ctx = context.WithValue(ctx, serviceKey, authReq.Service)
			}

			logger.Debug("Optional project authentication successful", map[string]interface{}{
				"service_name": serviceName,
			})

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Chain chains multiple middleware together
func Chain(middlewares ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		for i := len(middlewares) - 1; i >= 0; i-- {
			final = middlewares[i](final)
		}
		return final
	}
}

// Helper functions to extract authentication data from context

// GetAuthUser extracts the authenticated user from context
func GetAuthUser(ctx context.Context) (*types.AuthUser, bool) {
	user, ok := ctx.Value(authUserKey).(*types.AuthUser)
	return user, ok
}

// GetPlatformContext extracts the platform context from context
func GetPlatformContext(ctx context.Context) (*types.PlatformContext, bool) {
	platform, ok := ctx.Value(platformKey).(*types.PlatformContext)
	return platform, ok
}

// GetProjectContext extracts the project context from context
func GetProjectContext(ctx context.Context) (*types.ProjectContext, bool) {
	project, ok := ctx.Value(projectKey).(*types.ProjectContext)
	return project, ok
}

// GetServiceContext extracts the service context from context
func GetServiceContext(ctx context.Context) (*types.ServiceContext, bool) {
	service, ok := ctx.Value(serviceKey).(*types.ServiceContext)
	return service, ok
}

// GetAuthenticatedRequest extracts the full authenticated request from context
func GetAuthenticatedRequest(ctx context.Context) (*types.AuthenticatedRequest, bool) {
	authReq, ok := ctx.Value(authRequestKey).(*types.AuthenticatedRequest)
	return authReq, ok
}

// MustGetAuthUser extracts the authenticated user or panics
func MustGetAuthUser(ctx context.Context) *types.AuthUser {
	user, ok := GetAuthUser(ctx)
	if !ok {
		panic("no authenticated user found in context")
	}
	return user
}

// MustGetProjectContext extracts the project context or panics
func MustGetProjectContext(ctx context.Context) *types.ProjectContext {
	project, ok := GetProjectContext(ctx)
	if !ok {
		panic("no project context found in context")
	}
	return project
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "Unauthorized",
		"message": message,
	})
}

// writeScopeError writes a scope error response
func writeScopeError(w http.ResponseWriter, required, provided []string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "Forbidden",
		"message": "Insufficient permissions",
		"details": map[string]interface{}{
			"required": required,
			"provided": provided,
		},
	})
}
