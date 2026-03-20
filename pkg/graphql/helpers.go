package graphql

import (
	"context"
	"fmt"
	"net/http"

	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// ContextKey represents keys for storing values in context
type ContextKey string

const (
	// UserKey is the key for storing authenticated user in context
	UserKey ContextKey = "auth_user"
	// PlatformKey is the key for storing platform context in context
	PlatformKey ContextKey = "platform"
	// ProjectKey is the key for storing project context in context
	ProjectKey ContextKey = "project"
	// ServiceKey is the key for storing service context in context
	ServiceKey ContextKey = "service"
	// HTTPRequestKey is the key for storing the HTTP request in context
	HTTPRequestKey ContextKey = "http_request"
)

// GraphQLContext holds the authentication context for GraphQL resolvers
type GraphQLContext struct {
	User     *types.AuthUser
	Platform *types.PlatformContext
	Project  *types.ProjectContext
	Service  *types.ServiceContext
	Request  *http.Request
}

// AuthHelper provides authentication helpers for GraphQL resolvers
type AuthHelper struct {
	projectAuth *auth.ProjectAuthMiddleware
	userAuth    *auth.JwtAuthMiddleware
	serviceName string
}

// NewAuthHelper creates a new GraphQL authentication helper
func NewAuthHelper(serviceName string) *AuthHelper {
	return &AuthHelper{
		projectAuth: auth.NewProjectAuthMiddleware(serviceName),
		userAuth:    auth.NewJwtAuthMiddleware(),
		serviceName: serviceName,
	}
}

// AuthenticateUser authenticates a user token from the Authorization header
func (h *AuthHelper) AuthenticateUser(ctx context.Context) (*types.AuthUser, error) {
	req, err := GetHTTPRequest(ctx)
	if err != nil {
		return nil, err
	}

	user, err := h.userAuth.Authenticate(req)
	if err != nil {
		return nil, fmt.Errorf("user authentication failed: %w", err)
	}

	return user, nil
}

// AuthenticateProject authenticates a project/platform/service token from x-project-token header
func (h *AuthHelper) AuthenticateProject(ctx context.Context) (*types.AuthenticatedRequest, error) {
	req, err := GetHTTPRequest(ctx)
	if err != nil {
		return nil, err
	}

	authReq, err := h.projectAuth.Authenticate(req)
	if err != nil {
		return nil, fmt.Errorf("project authentication failed: %w", err)
	}

	return authReq, nil
}

// WithUserAuth wraps a resolver to require user authentication with optional scope checking
func (h *AuthHelper) WithUserAuth(resolver interface{}, requiredScopes ...string) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		user, err := h.AuthenticateUser(ctx)
		if err != nil {
			return nil, err
		}

		// Check scopes if provided
		if len(requiredScopes) > 0 {
			if !hasAllScopes(user.Permissions, requiredScopes) {
				return nil, fmt.Errorf("insufficient user permissions. Required: %v, Provided: %v", requiredScopes, user.Permissions)
			}
		}

		// Add user to context
		ctx = context.WithValue(ctx, UserKey, user)

		// Call resolver
		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// WithProjectAuth wraps a resolver to require project/platform/service authentication
func (h *AuthHelper) WithProjectAuth(resolver interface{}, requiredScopes ...string) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		authReq, err := h.AuthenticateProject(ctx)
		if err != nil {
			return nil, err
		}

		// Check scopes if provided
		if len(requiredScopes) > 0 {
			var scopes []string
			if authReq.Platform != nil {
				scopes = authReq.Platform.Scopes
			} else if authReq.Project != nil {
				scopes = authReq.Project.Scopes
			} else if authReq.Service != nil {
				scopes = authReq.Service.Scopes
			}

			if !hasAllScopes(scopes, requiredScopes) {
				return nil, fmt.Errorf("insufficient permissions. Required: %v, Provided: %v", requiredScopes, scopes)
			}
		}

		// Add auth context to context
		ctx = WithAuthenticatedRequest(ctx, authReq)

		// Call resolver
		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// WithCombinedAuth wraps a resolver to require BOTH user AND project authentication
func (h *AuthHelper) WithCombinedAuth(resolver interface{}, userScopes, projectScopes []string) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		// Authenticate user
		user, err := h.AuthenticateUser(ctx)
		if err != nil {
			return nil, err
		}

		// Check user scopes
		if len(userScopes) > 0 {
			if !hasAllScopes(user.Permissions, userScopes) {
				return nil, fmt.Errorf("insufficient user permissions. Required: %v, Provided: %v", userScopes, user.Permissions)
			}
		}

		// Authenticate project
		authReq, err := h.AuthenticateProject(ctx)
		if err != nil {
			return nil, err
		}

		// Check project scopes
		if len(projectScopes) > 0 {
			var scopes []string
			if authReq.Platform != nil {
				scopes = authReq.Platform.Scopes
			} else if authReq.Project != nil {
				scopes = authReq.Project.Scopes
			}

			if !hasAllScopes(scopes, projectScopes) {
				return nil, fmt.Errorf("insufficient project permissions. Required: %v, Provided: %v", projectScopes, scopes)
			}
		}

		// Add both to context
		ctx = context.WithValue(ctx, UserKey, user)
		ctx = WithAuthenticatedRequest(ctx, authReq)

		// Call resolver
		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// WithServiceAuth wraps a resolver to require service token authentication
func (h *AuthHelper) WithServiceAuth(resolver interface{}, requiredScopes ...string) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		authReq, err := h.AuthenticateProject(ctx)
		if err != nil {
			return nil, err
		}

		// Must be a service token
		if authReq.Service == nil {
			return nil, fmt.Errorf("this operation requires service authentication")
		}

		// Check scopes if provided
		if len(requiredScopes) > 0 {
			if !hasAllScopes(authReq.Service.Scopes, requiredScopes) {
				return nil, fmt.Errorf("insufficient service permissions. Required: %v, Provided: %v", requiredScopes, authReq.Service.Scopes)
			}
		}

		ctx = context.WithValue(ctx, ServiceKey, authReq.Service)

		// Call resolver
		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// WithServiceOrProjectAuth wraps a resolver to accept either service OR project/platform token
func (h *AuthHelper) WithServiceOrProjectAuth(resolver interface{}, serviceScopes, projectScopes []string) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		authReq, err := h.AuthenticateProject(ctx)
		if err != nil {
			return nil, err
		}

		if authReq.Service != nil {
			// Service token path
			if len(serviceScopes) > 0 {
				if !hasAllScopes(authReq.Service.Scopes, serviceScopes) {
					return nil, fmt.Errorf("insufficient service permissions. Required: %v, Provided: %v", serviceScopes, authReq.Service.Scopes)
				}
			}
			ctx = context.WithValue(ctx, ServiceKey, authReq.Service)
		} else if authReq.Project != nil || authReq.Platform != nil {
			// Project/platform token path
			if len(projectScopes) > 0 {
				var scopes []string
				if authReq.Platform != nil {
					scopes = authReq.Platform.Scopes
				} else {
					scopes = authReq.Project.Scopes
				}

				if !hasAllScopes(scopes, projectScopes) {
					return nil, fmt.Errorf("insufficient project permissions. Required: %v, Provided: %v", projectScopes, scopes)
				}
			}
			ctx = WithAuthenticatedRequest(ctx, authReq)
		} else {
			return nil, fmt.Errorf("this operation requires a service token or a project/platform token")
		}

		// Call resolver
		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// WithServiceOrUserAuth wraps a resolver to accept either service OR user token
func (h *AuthHelper) WithServiceOrUserAuth(resolver interface{}, serviceScopes, userScopes []string) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		var isService, isUser bool
		var authCtx context.Context

		// Try service token first
		authReq, err := h.AuthenticateProject(ctx)
		if err == nil && authReq.Service != nil {
			isService = true
			authCtx = context.WithValue(ctx, ServiceKey, authReq.Service)

			if len(serviceScopes) > 0 {
				if !hasAllScopes(authReq.Service.Scopes, serviceScopes) {
					return nil, fmt.Errorf("insufficient service permissions. Required: %v, Provided: %v", serviceScopes, authReq.Service.Scopes)
				}
			}
		} else {
			// Fall back to user token
			user, err := h.AuthenticateUser(ctx)
			if err == nil {
				isUser = true
				authCtx = context.WithValue(ctx, UserKey, user)

				if len(userScopes) > 0 {
					if !hasAllScopes(user.Permissions, userScopes) {
						return nil, fmt.Errorf("insufficient user permissions. Required: %v, Provided: %v", userScopes, user.Permissions)
					}
				}
			}
		}

		if !isService && !isUser {
			return nil, fmt.Errorf("this operation requires a service token or a user token")
		}

		// Call resolver
		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(authCtx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// OptionalUserAuth wraps a resolver with optional user authentication
func (h *AuthHelper) OptionalUserAuth(resolver interface{}) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		user, _ := h.AuthenticateUser(ctx)
		if user != nil {
			ctx = context.WithValue(ctx, UserKey, user)
		}

		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// OptionalProjectAuth wraps a resolver with optional project authentication
func (h *AuthHelper) OptionalProjectAuth(resolver interface{}) interface{} {
	return func(ctx context.Context, args interface{}) (interface{}, error) {
		authReq, _ := h.AuthenticateProject(ctx)
		if authReq != nil {
			ctx = WithAuthenticatedRequest(ctx, authReq)
		}

		if fn, ok := resolver.(func(context.Context, interface{}) (interface{}, error)); ok {
			return fn(ctx, args)
		}
		return nil, fmt.Errorf("invalid resolver signature")
	}
}

// GetCurrentUser extracts the authenticated user from context
func GetCurrentUser(ctx context.Context) (*types.AuthUser, error) {
	user, ok := ctx.Value(UserKey).(*types.AuthUser)
	if !ok || user == nil {
		return nil, fmt.Errorf("no authenticated user found in context")
	}
	return user, nil
}

// GetPlatformContext extracts the platform context from context
func GetPlatformContext(ctx context.Context) (*types.PlatformContext, error) {
	platform, ok := ctx.Value(PlatformKey).(*types.PlatformContext)
	if !ok || platform == nil {
		return nil, fmt.Errorf("no platform context found in context")
	}
	return platform, nil
}

// GetProjectContext extracts the project context from context
func GetProjectContext(ctx context.Context) (*types.ProjectContext, error) {
	project, ok := ctx.Value(ProjectKey).(*types.ProjectContext)
	if !ok || project == nil {
		return nil, fmt.Errorf("no project context found in context")
	}
	return project, nil
}

// GetServiceContext extracts the service context from context
func GetServiceContext(ctx context.Context) (*types.ServiceContext, error) {
	service, ok := ctx.Value(ServiceKey).(*types.ServiceContext)
	if !ok || service == nil {
		return nil, fmt.Errorf("no service context found in context")
	}
	return service, nil
}

// GetAuthenticatedRequest extracts the full authenticated request from context
func GetAuthenticatedRequest(ctx context.Context) (*types.AuthenticatedRequest, error) {
	req := &types.AuthenticatedRequest{}

	if user, err := GetCurrentUser(ctx); err == nil {
		req.User = user
	}
	if platform, err := GetPlatformContext(ctx); err == nil {
		req.Platform = platform
	}
	if project, err := GetProjectContext(ctx); err == nil {
		req.Project = project
	}
	if service, err := GetServiceContext(ctx); err == nil {
		req.Service = service
	}

	return req, nil
}

// WithAuthenticatedRequest adds all auth contexts to the context
func WithAuthenticatedRequest(ctx context.Context, authReq *types.AuthenticatedRequest) context.Context {
	if authReq.User != nil {
		ctx = context.WithValue(ctx, UserKey, authReq.User)
	}
	if authReq.Platform != nil {
		ctx = context.WithValue(ctx, PlatformKey, authReq.Platform)
	}
	if authReq.Project != nil {
		ctx = context.WithValue(ctx, ProjectKey, authReq.Project)
	}
	if authReq.Service != nil {
		ctx = context.WithValue(ctx, ServiceKey, authReq.Service)
	}
	return ctx
}

// GetHTTPRequest extracts the HTTP request from context
func GetHTTPRequest(ctx context.Context) (*http.Request, error) {
	req, ok := ctx.Value(HTTPRequestKey).(*http.Request)
	if !ok || req == nil {
		return nil, fmt.Errorf("no HTTP request found in context")
	}
	return req, nil
}

// WithHTTPRequest adds the HTTP request to the context
func WithHTTPRequest(ctx context.Context, req *http.Request) context.Context {
	return context.WithValue(ctx, HTTPRequestKey, req)
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
