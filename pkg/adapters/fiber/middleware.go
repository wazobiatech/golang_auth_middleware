package fiber

import (
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	futils "github.com/gofiber/fiber/v2/utils"
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

// Context locals keys for storing auth data
const (
	AuthUserKey    = "auth_user"
	AuthRequestKey = "auth_request"
	PlatformKey    = "platform"
	ProjectKey     = "project"
	ServiceKey     = "service"
)

// fiberToHTTPRequest converts Fiber context to http.Request for auth
func fiberToHTTPRequest(c *fiber.Ctx) *http.Request {
	// Create a new HTTP request from Fiber context
	// Note: We construct a minimal request with just the headers needed for auth
	req := &http.Request{
		Method: string(c.Method()),
		Header: make(http.Header),
	}

	// Copy headers
	c.Request().Header.VisitAll(func(key, value []byte) {
		req.Header.Set(futils.UnsafeString(key), futils.UnsafeString(value))
	})

	return req
}

// JWTMiddleware returns a Fiber middleware function for JWT authentication
func JWTMiddleware() fiber.Handler {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("fiber-jwt-middleware")

	return func(c *fiber.Ctx) error {
		req := fiberToHTTPRequest(c)
		user, err := jwtAuth.Authenticate(req)
		if err != nil {
			logger.Error("JWT authentication failed", map[string]interface{}{
				"error": err.Error(),
				"path":  c.Path(),
			})
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": err.Error(),
			})
		}

		// Store user in locals
		c.Locals(AuthUserKey, user)
		logger.Debug("JWT authentication successful", map[string]interface{}{
			"user_id": user.UUID,
			"email":   user.Email,
		})

		return c.Next()
	}
}

// ProjectMiddleware returns a Fiber middleware function for project/platform/service token authentication
func ProjectMiddleware(serviceName string) fiber.Handler {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("fiber-project-middleware")

	return func(c *fiber.Ctx) error {
		req := fiberToHTTPRequest(c)
		authReq, err := projectAuth.Authenticate(req)
		if err != nil {
			logger.Error("Project authentication failed", map[string]interface{}{
				"error":        err.Error(),
				"path":         c.Path(),
				"service_name": serviceName,
			})
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "Unauthorized",
				"message": err.Error(),
			})
		}

		// Store authentication context
		c.Locals(AuthRequestKey, authReq)

		if authReq.Platform != nil {
			c.Locals(PlatformKey, authReq.Platform)
			logger.Debug("Platform authentication successful", map[string]interface{}{
				"tenant_id": authReq.Platform.TenantID,
				"token_id":  authReq.Platform.TokenID,
			})
		}

		if authReq.Project != nil {
			c.Locals(ProjectKey, authReq.Project)
			logger.Debug("Project authentication successful", map[string]interface{}{
				"tenant_id":        authReq.Project.TenantID,
				"token_id":         authReq.Project.TokenID,
				"enabled_services": authReq.Project.EnabledServices,
			})
		}

		if authReq.Service != nil {
			c.Locals(ServiceKey, authReq.Service)
			logger.Debug("Service authentication successful", map[string]interface{}{
				"client_id":    authReq.Service.ClientID,
				"service_name": authReq.Service.ServiceName,
			})
		}

		return c.Next()
	}
}

// RequireScope returns a middleware that checks for specific scopes
func RequireScope(requiredScopes ...string) fiber.Handler {
	logger := utils.NewLogger("fiber-scope-middleware")

	return func(c *fiber.Ctx) error {
		if len(requiredScopes) == 0 {
			return c.Next()
		}

		var scopes []string

		// Try to get scopes from different auth contexts
		if authReq, ok := c.Locals(AuthRequestKey).(*types.AuthenticatedRequest); ok && authReq != nil {
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

				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error":   "Forbidden",
					"message": "Insufficient permissions",
					"details": fiber.Map{
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

		return c.Next()
	}
}

// OptionalJWTMiddleware provides JWT authentication but doesn't require it
func OptionalJWTMiddleware() fiber.Handler {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("fiber-optional-jwt-middleware")

	return func(c *fiber.Ctx) error {
		req := fiberToHTTPRequest(c)
		user, err := jwtAuth.Authenticate(req)
		if err != nil {
			logger.Debug("Optional JWT authentication failed", map[string]interface{}{
				"error": err.Error(),
				"path":  c.Path(),
			})
			// Continue without authentication
			return c.Next()
		}

		// Store user in locals if authentication succeeded
		c.Locals(AuthUserKey, user)
		logger.Debug("Optional JWT authentication successful", map[string]interface{}{
			"user_id": user.UUID,
			"email":   user.Email,
		})

		return c.Next()
	}
}

// OptionalProjectMiddleware provides project authentication but doesn't require it
func OptionalProjectMiddleware(serviceName string) fiber.Handler {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("fiber-optional-project-middleware")

	return func(c *fiber.Ctx) error {
		req := fiberToHTTPRequest(c)
		authReq, err := projectAuth.Authenticate(req)
		if err != nil {
			logger.Debug("Optional project authentication failed", map[string]interface{}{
				"error":        err.Error(),
				"path":         c.Path(),
				"service_name": serviceName,
			})
			// Continue without project authentication
			return c.Next()
		}

		// Store authentication context if successful
		c.Locals(AuthRequestKey, authReq)

		if authReq.Platform != nil {
			c.Locals(PlatformKey, authReq.Platform)
		}
		if authReq.Project != nil {
			c.Locals(ProjectKey, authReq.Project)
		}
		if authReq.Service != nil {
			c.Locals(ServiceKey, authReq.Service)
		}

		logger.Debug("Optional project authentication successful", map[string]interface{}{
			"service_name": serviceName,
		})

		return c.Next()
	}
}

// Helper functions to extract authentication data from Fiber context

// GetAuthUser extracts the authenticated user from Fiber context
func GetAuthUser(c *fiber.Ctx) (*types.AuthUser, bool) {
	user, ok := c.Locals(AuthUserKey).(*types.AuthUser)
	return user, ok
}

// GetPlatformContext extracts the platform context from Fiber context
func GetPlatformContext(c *fiber.Ctx) (*types.PlatformContext, bool) {
	platform, ok := c.Locals(PlatformKey).(*types.PlatformContext)
	return platform, ok
}

// GetProjectContext extracts the project context from Fiber context
func GetProjectContext(c *fiber.Ctx) (*types.ProjectContext, bool) {
	project, ok := c.Locals(ProjectKey).(*types.ProjectContext)
	return project, ok
}

// GetServiceContext extracts the service context from Fiber context
func GetServiceContext(c *fiber.Ctx) (*types.ServiceContext, bool) {
	service, ok := c.Locals(ServiceKey).(*types.ServiceContext)
	return service, ok
}

// GetAuthenticatedRequest extracts the full authenticated request from Fiber context
func GetAuthenticatedRequest(c *fiber.Ctx) (*types.AuthenticatedRequest, bool) {
	authReq, ok := c.Locals(AuthRequestKey).(*types.AuthenticatedRequest)
	return authReq, ok
}

// MustGetAuthUser extracts the authenticated user or panics
func MustGetAuthUser(c *fiber.Ctx) *types.AuthUser {
	user, ok := GetAuthUser(c)
	if !ok {
		panic("no authenticated user found in context")
	}
	return user
}

// MustGetProjectContext extracts the project context or panics
func MustGetProjectContext(c *fiber.Ctx) *types.ProjectContext {
	project, ok := GetProjectContext(c)
	if !ok {
		panic("no project context found in context")
	}
	return project
}

// hasAllScopes checks if the provided scopes contain all required scopes
func hasAllScopes(provided, required []string) bool {
	scopeSet := make(map[string]bool)
	for _, s := range provided {
		scopeSet[s] = true
	}

	for _, r := range required {
		if !scopeSet[r] {
			return false
		}
	}
	return true
}

// extractToken extracts Bearer token from header
func extractToken(header string) string {
	if strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	return header
}
