package echo

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

// Context keys for storing auth data
const (
	AuthUserKey    = "auth_user"
	AuthRequestKey = "auth_request"
	PlatformKey    = "platform"
	ProjectKey     = "project"
	ServiceKey     = "service"
)

// JWTMiddleware returns an Echo middleware function for JWT authentication
func JWTMiddleware() echo.MiddlewareFunc {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("echo-jwt-middleware")

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, err := jwtAuth.Authenticate(c.Request())
			if err != nil {
				logger.Error("JWT authentication failed", map[string]interface{}{
					"error": err.Error(),
					"path":  c.Request().URL.Path,
				})
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"error":   "Unauthorized",
					"message": err.Error(),
				})
			}

			// Store user in context
			c.Set(AuthUserKey, user)
			logger.Debug("JWT authentication successful", map[string]interface{}{
				"user_id": user.UUID,
				"email":   user.Email,
			})

			return next(c)
		}
	}
}

// ProjectMiddleware returns an Echo middleware function for project/platform/service token authentication
func ProjectMiddleware(serviceName string) echo.MiddlewareFunc {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("echo-project-middleware")

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authReq, err := projectAuth.Authenticate(c.Request())
			if err != nil {
				logger.Error("Project authentication failed", map[string]interface{}{
					"error":        err.Error(),
					"path":         c.Request().URL.Path,
					"service_name": serviceName,
				})
				return c.JSON(http.StatusUnauthorized, map[string]interface{}{
					"error":   "Unauthorized",
					"message": err.Error(),
				})
			}

			// Store authentication context
			c.Set(AuthRequestKey, authReq)

			if authReq.Platform != nil {
				c.Set(PlatformKey, authReq.Platform)
				logger.Debug("Platform authentication successful", map[string]interface{}{
					"tenant_id": authReq.Platform.TenantID,
					"token_id":  authReq.Platform.TokenID,
				})
			}

			if authReq.Project != nil {
				c.Set(ProjectKey, authReq.Project)
				logger.Debug("Project authentication successful", map[string]interface{}{
					"tenant_id":        authReq.Project.TenantID,
					"token_id":         authReq.Project.TokenID,
					"enabled_services": authReq.Project.EnabledServices,
				})
			}

			if authReq.Service != nil {
				c.Set(ServiceKey, authReq.Service)
				logger.Debug("Service authentication successful", map[string]interface{}{
					"client_id":    authReq.Service.ClientID,
					"service_name": authReq.Service.ServiceName,
				})
			}

			return next(c)
		}
	}
}

// RequireScope returns a middleware that checks for specific scopes
func RequireScope(requiredScopes ...string) echo.MiddlewareFunc {
	logger := utils.NewLogger("echo-scope-middleware")

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if len(requiredScopes) == 0 {
				return next(c)
			}

			var scopes []string

			// Try to get scopes from different auth contexts
			if authReq, ok := c.Get(AuthRequestKey).(*types.AuthenticatedRequest); ok && authReq != nil {
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

					return c.JSON(http.StatusForbidden, map[string]interface{}{
						"error":   "Forbidden",
						"message": "Insufficient permissions",
						"details": map[string]interface{}{
							"required": requiredScopes,
							"provided": scopes,
						},
					})
				}
			}

			logger.Debug("Scope validation passed", map[string]interface{}{
				"required_scopes": requiredScopes,
				"user_scopes":     scopes,
			})

			return next(c)
		}
	}
}

// OptionalJWTMiddleware provides JWT authentication but doesn't require it
func OptionalJWTMiddleware() echo.MiddlewareFunc {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("echo-optional-jwt-middleware")

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, err := jwtAuth.Authenticate(c.Request())
			if err != nil {
				logger.Debug("Optional JWT authentication failed", map[string]interface{}{
					"error": err.Error(),
					"path":  c.Request().URL.Path,
				})
				// Continue without authentication
				return next(c)
			}

			// Store user in context if authentication succeeded
			c.Set(AuthUserKey, user)
			logger.Debug("Optional JWT authentication successful", map[string]interface{}{
				"user_id": user.UUID,
				"email":   user.Email,
			})

			return next(c)
		}
	}
}

// OptionalProjectMiddleware provides project authentication but doesn't require it
func OptionalProjectMiddleware(serviceName string) echo.MiddlewareFunc {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("echo-optional-project-middleware")

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			authReq, err := projectAuth.Authenticate(c.Request())
			if err != nil {
				logger.Debug("Optional project authentication failed", map[string]interface{}{
					"error":        err.Error(),
					"path":         c.Request().URL.Path,
					"service_name": serviceName,
				})
				// Continue without project authentication
				return next(c)
			}

			// Store authentication context if successful
			c.Set(AuthRequestKey, authReq)

			if authReq.Platform != nil {
				c.Set(PlatformKey, authReq.Platform)
			}
			if authReq.Project != nil {
				c.Set(ProjectKey, authReq.Project)
			}
			if authReq.Service != nil {
				c.Set(ServiceKey, authReq.Service)
			}

			logger.Debug("Optional project authentication successful", map[string]interface{}{
				"service_name": serviceName,
			})

			return next(c)
		}
	}
}

// Helper functions to extract authentication data from Echo context

// GetAuthUser extracts the authenticated user from Echo context
func GetAuthUser(c echo.Context) (*types.AuthUser, bool) {
	user, exists := c.Get(AuthUserKey).(*types.AuthUser)
	return user, exists
}

// GetPlatformContext extracts the platform context from Echo context
func GetPlatformContext(c echo.Context) (*types.PlatformContext, bool) {
	platform, exists := c.Get(PlatformKey).(*types.PlatformContext)
	return platform, exists
}

// GetProjectContext extracts the project context from Echo context
func GetProjectContext(c echo.Context) (*types.ProjectContext, bool) {
	project, exists := c.Get(ProjectKey).(*types.ProjectContext)
	return project, exists
}

// GetServiceContext extracts the service context from Echo context
func GetServiceContext(c echo.Context) (*types.ServiceContext, bool) {
	service, exists := c.Get(ServiceKey).(*types.ServiceContext)
	return service, exists
}

// GetAuthenticatedRequest extracts the full authenticated request from Echo context
func GetAuthenticatedRequest(c echo.Context) (*types.AuthenticatedRequest, bool) {
	authReq, exists := c.Get(AuthRequestKey).(*types.AuthenticatedRequest)
	return authReq, exists
}

// MustGetAuthUser extracts the authenticated user or returns error
func MustGetAuthUser(c echo.Context) (*types.AuthUser, error) {
	user, ok := GetAuthUser(c)
	if !ok {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "no authenticated user found in context")
	}
	return user, nil
}

// MustGetProjectContext extracts the project context or returns error
func MustGetProjectContext(c echo.Context) (*types.ProjectContext, error) {
	project, ok := GetProjectContext(c)
	if !ok {
		return nil, echo.NewHTTPError(http.StatusUnauthorized, "no project context found in context")
	}
	return project, nil
}
