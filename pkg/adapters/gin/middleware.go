package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wazobiatech/golang_auth_middleware/pkg/auth"
	"github.com/wazobiatech/golang_auth_middleware/pkg/types"
	"github.com/wazobiatech/golang_auth_middleware/pkg/utils"
)

// Middleware keys for storing auth data in Gin context
const (
	AuthUserKey    = "auth_user"
	AuthRequestKey = "auth_request"
	PlatformKey    = "platform"
	ProjectKey     = "project"
	ServiceKey     = "service"
)

// JWTMiddleware returns a Gin middleware function for JWT authentication
func JWTMiddleware() gin.HandlerFunc {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("gin-jwt-middleware")

	return func(c *gin.Context) {
		user, err := jwtAuth.Authenticate(c.Request)
		if err != nil {
			logger.Error("JWT authentication failed", map[string]interface{}{
				"error": err.Error(),
				"path":  c.Request.URL.Path,
			})

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Store user in context
		c.Set(AuthUserKey, user)
		logger.Debug("JWT authentication successful", map[string]interface{}{
			"user_id": user.UUID,
			"email":   user.Email,
		})

		c.Next()
	}
}

// ProjectMiddleware returns a Gin middleware function for project/platform/service token authentication
func ProjectMiddleware(serviceName string) gin.HandlerFunc {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("gin-project-middleware")

	return func(c *gin.Context) {
		authReq, err := projectAuth.Authenticate(c.Request)
		if err != nil {
			logger.Error("Project authentication failed", map[string]interface{}{
				"error":        err.Error(),
				"path":         c.Request.URL.Path,
				"service_name": serviceName,
			})

			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "Unauthorized",
				"message": err.Error(),
			})
			c.Abort()
			return
		}

		// Store authentication context in Gin context
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

		c.Next()
	}
}

// RequireScope returns a middleware that checks for specific scopes
func RequireScope(requiredScopes ...string) gin.HandlerFunc {
	logger := utils.NewLogger("gin-scope-middleware")

	return func(c *gin.Context) {
		if len(requiredScopes) == 0 {
			c.Next()
			return
		}

		var scopes []string

		// Try to get scopes from different auth contexts
		if authReq, exists := c.Get(AuthRequestKey); exists {
			if req, ok := authReq.(*types.AuthenticatedRequest); ok {
				if req.Platform != nil {
					scopes = req.Platform.Scopes
				} else if req.Project != nil {
					scopes = req.Project.Scopes
				} else if req.Service != nil {
					scopes = req.Service.Scopes
				}
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

				c.JSON(http.StatusForbidden, gin.H{
					"error":   "Forbidden",
					"message": "Insufficient permissions",
					"details": map[string]interface{}{
						"required": requiredScopes,
						"provided": scopes,
					},
				})
				c.Abort()
				return
			}
		}

		logger.Debug("Scope validation passed", map[string]interface{}{
			"required_scopes": requiredScopes,
			"user_scopes":     scopes,
		})

		c.Next()
	}
}

// OptionalJWTMiddleware provides JWT authentication but doesn't require it
func OptionalJWTMiddleware() gin.HandlerFunc {
	jwtAuth := auth.NewJwtAuthMiddleware()
	logger := utils.NewLogger("gin-optional-jwt-middleware")

	return func(c *gin.Context) {
		user, err := jwtAuth.Authenticate(c.Request)
		if err != nil {
			logger.Debug("Optional JWT authentication failed", map[string]interface{}{
				"error": err.Error(),
				"path":  c.Request.URL.Path,
			})
			// Continue without authentication
			c.Next()
			return
		}

		// Store user in context if authentication succeeded
		c.Set(AuthUserKey, user)
		logger.Debug("Optional JWT authentication successful", map[string]interface{}{
			"user_id": user.UUID,
			"email":   user.Email,
		})

		c.Next()
	}
}

// OptionalProjectMiddleware provides project authentication but doesn't require it
func OptionalProjectMiddleware(serviceName string) gin.HandlerFunc {
	projectAuth := auth.NewProjectAuthMiddleware(serviceName)
	logger := utils.NewLogger("gin-optional-project-middleware")

	return func(c *gin.Context) {
		authReq, err := projectAuth.Authenticate(c.Request)
		if err != nil {
			logger.Debug("Optional project authentication failed", map[string]interface{}{
				"error":        err.Error(),
				"path":         c.Request.URL.Path,
				"service_name": serviceName,
			})
			// Continue without project authentication
			c.Next()
			return
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

		c.Next()
	}
}

// Helper functions to extract authentication data from Gin context

// GetAuthUser extracts the authenticated user from Gin context
func GetAuthUser(c *gin.Context) (*types.AuthUser, bool) {
	user, exists := c.Get(AuthUserKey)
	if !exists {
		return nil, false
	}

	authUser, ok := user.(*types.AuthUser)
	return authUser, ok
}

// GetPlatformContext extracts the platform context from Gin context
func GetPlatformContext(c *gin.Context) (*types.PlatformContext, bool) {
	platform, exists := c.Get(PlatformKey)
	if !exists {
		return nil, false
	}

	platformCtx, ok := platform.(*types.PlatformContext)
	return platformCtx, ok
}

// GetProjectContext extracts the project context from Gin context
func GetProjectContext(c *gin.Context) (*types.ProjectContext, bool) {
	project, exists := c.Get(ProjectKey)
	if !exists {
		return nil, false
	}

	projectCtx, ok := project.(*types.ProjectContext)
	return projectCtx, ok
}

// GetServiceContext extracts the service context from Gin context
func GetServiceContext(c *gin.Context) (*types.ServiceContext, bool) {
	service, exists := c.Get(ServiceKey)
	if !exists {
		return nil, false
	}

	serviceCtx, ok := service.(*types.ServiceContext)
	return serviceCtx, ok
}

// GetAuthenticatedRequest extracts the full authenticated request from Gin context
func GetAuthenticatedRequest(c *gin.Context) (*types.AuthenticatedRequest, bool) {
	authReq, exists := c.Get(AuthRequestKey)
	if !exists {
		return nil, false
	}

	req, ok := authReq.(*types.AuthenticatedRequest)
	return req, ok
}

// MustGetAuthUser extracts the authenticated user or panics
func MustGetAuthUser(c *gin.Context) *types.AuthUser {
	user, ok := GetAuthUser(c)
	if !ok {
		panic("no authenticated user found in context")
	}
	return user
}

// MustGetProjectContext extracts the project context or panics
func MustGetProjectContext(c *gin.Context) *types.ProjectContext {
	project, ok := GetProjectContext(c)
	if !ok {
		panic("no project context found in context")
	}
	return project
}