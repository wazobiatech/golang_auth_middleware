// Package authmiddleware provides authentication middleware for Go applications
// compatible with the Mercury authentication service.
//
// This package provides:
//   - JWT authentication for user tokens
//   - Project/Platform/Service token authentication
//   - Framework-specific adapters (Gin, Echo, Fiber, Chi, net/http)
//   - GraphQL authentication helpers
//   - Redis-backed caching
//   - JWKS key management
//
// Basic usage with net/http:
//
//	package main
//
//	import (
//	    "net/http"
//	    authmiddleware "github.com/wazobiatech/auth-middleware-go"
//	)
//
//	func main() {
//	    // JWT authentication
//	    http.Handle("/protected", authmiddleware.JWTMiddleware(http.HandlerFunc(handler)))
//
//	    // Project authentication
//	    http.Handle("/api/", authmiddleware.ProjectMiddleware("my-service")(http.HandlerFunc(handler)))
//
//	    http.ListenAndServe(":8080", nil)
//	}
//
package authmiddleware

import (
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/client"
	"github.com/wazobiatech/auth-middleware-go/pkg/graphql"
	"github.com/wazobiatech/auth-middleware-go/pkg/jwks"
	"github.com/wazobiatech/auth-middleware-go/pkg/middleware"
	"github.com/wazobiatech/auth-middleware-go/pkg/redis"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
	"github.com/wazobiatech/auth-middleware-go/pkg/utils"

	// Framework adapters
	echoAdapter "github.com/wazobiatech/auth-middleware-go/pkg/adapters/echo"
	fiberAdapter "github.com/wazobiatech/auth-middleware-go/pkg/adapters/fiber"
	chiAdapter "github.com/wazobiatech/auth-middleware-go/pkg/adapters/chi"
	ginAdapter "github.com/wazobiatech/auth-middleware-go/pkg/adapters/gin"
	nethttpAdapter "github.com/wazobiatech/auth-middleware-go/pkg/adapters/nethttp"
)

// Re-export types
 type (
	 AuthUser            = types.AuthUser
	 AuthenticatedRequest = types.AuthenticatedRequest
	 PlatformContext     = types.PlatformContext
	 ProjectContext      = types.ProjectContext
	 ServiceContext      = types.ServiceContext
	 PlatformTokenPayload = types.PlatformTokenPayload
	 ProjectTokenPayload  = types.ProjectTokenPayload
	 ServiceTokenPayload  = types.ServiceTokenPayload
	 UserTokenPayload     = types.UserTokenPayload
	 JwtPayload          = types.JwtPayload
	 AuthError           = types.AuthError
 )

 // Re-export auth errors
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

 // Re-export main types and constructors
 var (
	 NewJwtAuthMiddleware    = auth.NewJwtAuthMiddleware
	 NewProjectAuthMiddleware = auth.NewProjectAuthMiddleware
	 NewAuthHelper           = graphql.NewAuthHelper
	 NewServiceClient        = client.NewServiceClient
	 NewCache                = jwks.NewCache
	 NewKeyStore             = jwks.NewKeyStore
	 NewClient               = redis.NewClient
	 NewLogger               = utils.NewLogger
	 GetConfig               = utils.GetConfig
	 UpdateConfig            = utils.UpdateConfig
	 PrintConfig             = utils.PrintConfig
 )

 // net/http adapters
 var (
	 // JWTMiddleware wraps a handler with JWT authentication
	 JWTMiddleware = nethttpAdapter.JWTMiddleware
	 // ProjectMiddleware creates project authentication middleware
	 ProjectMiddleware = nethttpAdapter.ProjectMiddleware
	 // RequireScope creates scope checking middleware
	 RequireScope = nethttpAdapter.RequireScope
	 // OptionalJWTMiddleware creates optional JWT authentication middleware
	 OptionalJWTMiddleware = nethttpAdapter.OptionalJWTMiddleware
	 // OptionalProjectMiddleware creates optional project authentication middleware
	 OptionalProjectMiddleware = nethttpAdapter.OptionalProjectMiddleware
	 // Chain chains multiple middleware together
	 Chain = nethttpAdapter.Chain
 )

 // Gin adapters
 var (
	 // GinJWTMiddleware returns Gin JWT middleware
	 GinJWTMiddleware = ginAdapter.JWTMiddleware
	 // GinProjectMiddleware returns Gin project middleware
	 GinProjectMiddleware = ginAdapter.ProjectMiddleware
	 // GinRequireScope returns Gin scope middleware
	 GinRequireScope = ginAdapter.RequireScope
	 // GinOptionalJWTMiddleware returns optional Gin JWT middleware
	 GinOptionalJWTMiddleware = ginAdapter.OptionalJWTMiddleware
	 // GinOptionalProjectMiddleware returns optional Gin project middleware
	 GinOptionalProjectMiddleware = ginAdapter.OptionalProjectMiddleware
	 // GinGetAuthUser extracts user from Gin context
	 GinGetAuthUser = ginAdapter.GetAuthUser
	 // GinGetPlatformContext extracts platform from Gin context
	 GinGetPlatformContext = ginAdapter.GetPlatformContext
	 // GinGetProjectContext extracts project from Gin context
	 GinGetProjectContext = ginAdapter.GetProjectContext
	 // GinGetServiceContext extracts service from Gin context
	 GinGetServiceContext = ginAdapter.GetServiceContext
 )

 // Echo adapters
 var (
	 // EchoJWTMiddleware returns Echo JWT middleware
	 EchoJWTMiddleware = echoAdapter.JWTMiddleware
	 // EchoProjectMiddleware returns Echo project middleware
	 EchoProjectMiddleware = echoAdapter.ProjectMiddleware
	 // EchoRequireScope returns Echo scope middleware
	 EchoRequireScope = echoAdapter.RequireScope
	 // EchoOptionalJWTMiddleware returns optional Echo JWT middleware
	 EchoOptionalJWTMiddleware = echoAdapter.OptionalJWTMiddleware
	 // EchoOptionalProjectMiddleware returns optional Echo project middleware
	 EchoOptionalProjectMiddleware = echoAdapter.OptionalProjectMiddleware
	 // EchoGetAuthUser extracts user from Echo context
	 EchoGetAuthUser = echoAdapter.GetAuthUser
	 // EchoGetPlatformContext extracts platform from Echo context
	 EchoGetPlatformContext = echoAdapter.GetPlatformContext
	 // EchoGetProjectContext extracts project from Echo context
	 EchoGetProjectContext = echoAdapter.GetProjectContext
	 // EchoGetServiceContext extracts service from Echo context
	 EchoGetServiceContext = echoAdapter.GetServiceContext
 )

 // Fiber adapters
 var (
	 // FiberJWTMiddleware returns Fiber JWT middleware
	 FiberJWTMiddleware = fiberAdapter.JWTMiddleware
	 // FiberProjectMiddleware returns Fiber project middleware
	 FiberProjectMiddleware = fiberAdapter.ProjectMiddleware
	 // FiberRequireScope returns Fiber scope middleware
	 FiberRequireScope = fiberAdapter.RequireScope
	 // FiberOptionalJWTMiddleware returns optional Fiber JWT middleware
	 FiberOptionalJWTMiddleware = fiberAdapter.OptionalJWTMiddleware
	 // FiberOptionalProjectMiddleware returns optional Fiber project middleware
	 FiberOptionalProjectMiddleware = fiberAdapter.OptionalProjectMiddleware
	 // FiberGetAuthUser extracts user from Fiber context
	 FiberGetAuthUser = fiberAdapter.GetAuthUser
	 // FiberGetPlatformContext extracts platform from Fiber context
	 FiberGetPlatformContext = fiberAdapter.GetPlatformContext
	 // FiberGetProjectContext extracts project from Fiber context
	 FiberGetProjectContext = fiberAdapter.GetProjectContext
	 // FiberGetServiceContext extracts service from Fiber context
	 FiberGetServiceContext = fiberAdapter.GetServiceContext
 )

 // Chi adapters
 var (
	 // ChiJWTMiddleware returns Chi JWT middleware
	 ChiJWTMiddleware = chiAdapter.JWTMiddleware
	 // ChiProjectMiddleware returns Chi project middleware
	 ChiProjectMiddleware = chiAdapter.ProjectMiddleware
	 // ChiRequireScope returns Chi scope middleware
	 ChiRequireScope = chiAdapter.RequireScope
	 // ChiOptionalJWTMiddleware returns optional Chi JWT middleware
	 ChiOptionalJWTMiddleware = chiAdapter.OptionalJWTMiddleware
	 // ChiOptionalProjectMiddleware returns optional Chi project middleware
	 ChiOptionalProjectMiddleware = chiAdapter.OptionalProjectMiddleware
	 // ChiGetAuthUser extracts user from Chi context
	 ChiGetAuthUser = chiAdapter.GetAuthUser
	 // ChiGetPlatformContext extracts platform from Chi context
	 ChiGetPlatformContext = chiAdapter.GetPlatformContext
	 // ChiGetProjectContext extracts project from Chi context
	 ChiGetProjectContext = chiAdapter.GetProjectContext
	 // ChiGetServiceContext extracts service from Chi context
	 ChiGetServiceContext = chiAdapter.GetServiceContext
 )

 // GraphQL helpers
 var (
	 // GraphQLGetCurrentUser extracts user from GraphQL context
	 GraphQLGetCurrentUser = graphql.GetCurrentUser
	 // GraphQLGetPlatformContext extracts platform from GraphQL context
	 GraphQLGetPlatformContext = graphql.GetPlatformContext
	 // GraphQLGetProjectContext extracts project from GraphQL context
	 GraphQLGetProjectContext = graphql.GetProjectContext
	 // GraphQLGetServiceContext extracts service from GraphQL context
	 GraphQLGetServiceContext = graphql.GetServiceContext
	 // GraphQLWithHTTPRequest adds HTTP request to GraphQL context
	 GraphQLWithHTTPRequest = graphql.WithHTTPRequest
 )

 // Middleware aliases for backward compatibility
 var (
	 ProjectAuthMiddleware = middleware.NewProjectAuthMiddleware
	 JwtAuthMiddleware     = middleware.NewJwtAuthMiddleware
 )
