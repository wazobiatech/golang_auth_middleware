package graphql

import (
	"net/http"

	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

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
func (h *GraphQLAuthHelper) WithUserAuth(resolver func(interface{}, interface{}, *types.AuthenticatedRequest) (interface{}, error)) func(interface{}, interface{}, *http.Request) (interface{}, error) {
	return func(parent interface{}, args interface{}, req *http.Request) (interface{}, error) {
		if req == nil {
			return nil, &types.AuthError{
				Code:    types.ErrCodeMissingHeader,
				Message: "Request context not available",
			}
		}

		user, err := h.userAuth.Authenticate(req)
		if err != nil {
			return nil, err
		}

		authReq := &types.AuthenticatedRequest{
			User: user,
		}
		return resolver(parent, args, authReq)
	}
}

// WithProjectAuth wraps a resolver to require project/platform token
func (h *GraphQLAuthHelper) WithProjectAuth(resolver func(interface{}, interface{}, *types.AuthenticatedRequest) (interface{}, error)) func(interface{}, interface{}, *http.Request) (interface{}, error) {
	return func(parent interface{}, args interface{}, req *http.Request) (interface{}, error) {
		if req == nil {
			return nil, &types.AuthError{
				Code:    types.ErrCodeMissingHeader,
				Message: "Request context not available",
			}
		}

		authReq, err := h.projectAuth.Authenticate(req)
		if err != nil {
			return nil, err
		}

		return resolver(parent, args, authReq)
	}
}

// AuthenticateUser directly authenticates a user token and populates the request
func (h *GraphQLAuthHelper) AuthenticateUser(req *http.Request) (*types.AuthUser, error) {
	if req == nil {
		return nil, &types.AuthError{
			Code:    types.ErrCodeMissingHeader,
			Message: "Request context not available",
		}
	}

	return h.userAuth.Authenticate(req)
}

// AuthenticateProject directly authenticates a project token and populates the request
func (h *GraphQLAuthHelper) AuthenticateProject(req *http.Request) (*types.AuthenticatedRequest, error) {
	if req == nil {
		return nil, &types.AuthError{
			Code:    types.ErrCodeMissingHeader,
			Message: "Request context not available",
		}
	}

	return h.projectAuth.Authenticate(req)
}