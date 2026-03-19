package graphql

import (
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

var _ *auth.JwtAuthMiddleware // Import check

// GraphQLAuthHelper provides wrapper methods for GraphQL resolver authentication
type GraphQLAuthHelper struct {
	projectAuth *auth.ProjectAuthMiddleware
	userAuth    *auth.JwtAuthMiddleware
}

// NewGraphQLAuthHelper creates a new GraphQL authentication helper
func NewGraphQLAuthHelper(serviceName string) *GraphQLAuthHelper {
	return &GraphQLAuthHelper{
		projectAuth: auth.NewProjectAuthMiddleware(serviceName),
		userAuth:    auth.NewJwtAuthMiddleware(),
	}
}

// WithUserAuth wraps a resolver to require user JWT authentication
func (h *GraphQLAuthHelper) WithUserAuth(resolver func(interface{}, interface{}, *types.AuthenticatedRequest) (interface{}, error)) func(interface{}, interface{}, *types.AuthenticatedRequest) (interface{}, error) {
	return func(parent interface{}, args interface{}, context *types.AuthenticatedRequest) (interface{}, error) {
		if context == nil {
			return nil, &types.AuthError{
				Code:    types.ErrCodeMissingHeader,
				Message: "Request context not available",
			}
		}

		user, err := h.userAuth.Authenticate(context.Request())
		if err != nil {
			return nil, err
		}

		context.User = user
		return resolver(parent, args, context)
	}
}

// WithProjectAuth wraps a resolver to require project/platform token
func (h *GraphQLAuthHelper) WithProjectAuth(resolver func(interface{}, interface{}, *types.AuthenticatedRequest) (interface{}, error)) func(interface{}, interface{}, *types.AuthenticatedRequest) (interface{}, error) {
	return func(parent interface{}, args interface{}, context *types.AuthenticatedRequest) (interface{}, error) {
		if context == nil {
			return nil, &types.AuthError{
				Code:    types.ErrCodeMissingHeader,
				Message: "Request context not available",
			}
		}

		authReq, err := h.projectAuth.Authenticate(context.Request())
		if err != nil {
			return nil, err
		}

		// Copy project data to context
		context.Platform = authReq.Platform
		context.Project = authReq.Project
		context.Service = authReq.Service

		return resolver(parent, args, context)
	}
}

// AuthenticateUser directly authenticates a user token and populates the context
func (h *GraphQLAuthHelper) AuthenticateUser(req *types.AuthenticatedRequest) error {
	if req.Request() == nil {
		return &types.AuthError{
			Code:    types.ErrCodeMissingHeader,
			Message: "Request context not available",
		}
	}

	user, err := h.userAuth.Authenticate(req.Request())
	if err != nil {
		return err
	}

	req.User = user
	return nil
}

// AuthenticateProject directly authenticates a project token and populates the context
func (h *GraphQLAuthHelper) AuthenticateProject(req *types.AuthenticatedRequest) error {
	if req.Request() == nil {
		return &types.AuthError{
			Code:    types.ErrCodeMissingHeader,
			Message: "Request context not available",
		}
	}

	authReq, err := h.projectAuth.Authenticate(req.Request())
	if err != nil {
		return err
	}

	req.Platform = authReq.Platform
	req.Project = authReq.Project
	req.Service = authReq.Service
	return nil
}