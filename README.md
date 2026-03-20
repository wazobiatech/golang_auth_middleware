# Go Auth Middleware

A comprehensive authentication middleware library for Go applications, compatible with the Mercury authentication service. This library provides JWT authentication, project/platform/service token validation, and framework-specific adapters.

## Features

- **JWT Authentication**: Validate user tokens with JWKS support
- **Project/Platform/Service Token Authentication**: Handle different token types
- **Redis Caching**: Cached JWKS and token validation for performance
- **Multi-Framework Support**: Adapters for Gin, Echo, Fiber, Chi, and net/http
- **GraphQL Support**: Authentication helpers for GraphQL resolvers
- **Scope Validation**: Permission/scope checking for protected routes
- **Auto-Refresh**: Automatic JWKS refresh on key miss
- **Service Enablement**: Verify services are enabled for projects

## Installation

```bash
go get github.com/wazobiatech/auth-middleware-go
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MERCURY_BASE_URL` | Mercury authentication service URL | `http://localhost:4000` |
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `REDIS_PASSWORD` | Redis password | `` |
| `REDIS_DB` | Redis database number | `0` |
| `CLIENT_ID` | Service client ID | `` |
| `CLIENT_SECRET` | Service client secret | `` |
| `SIGNATURE_SHARED_SECRET` | HMAC signature secret | `` |
| `CACHE_EXPIRY_TIME` | Token cache expiry (seconds) | `3600` |
| `JWKS_CACHE_TTL` | JWKS cache TTL (seconds) | `18000` |
| `SERVICE_TOKEN_CACHE_TTL` | Service token cache TTL (seconds) | `3300` |
| `SERVICE_UUID_CACHE_TTL` | Service UUID cache TTL (seconds) | `86400` |
| `LOG_LEVEL` | Logging level (debug, info, warn, error) | `info` |

## Quick Start

### Using with net/http

```go
package main

import (
    "net/http"
    authmiddleware "github.com/wazobiatech/auth-middleware-go"
)

func main() {
    // Protected route with JWT authentication
    http.Handle("/user", authmiddleware.JWTMiddleware(
        http.HandlerFunc(userHandler),
    ))

    // Protected route with project authentication
    http.Handle("/api/", authmiddleware.ProjectMiddleware("my-service")(
        http.HandlerFunc(apiHandler),
    ))

    // Route with scope checking
    http.Handle("/admin", authmiddleware.Chain(
        authmiddleware.ProjectMiddleware("my-service"),
        authmiddleware.RequireScope("admin:read"),
    )(http.HandlerFunc(adminHandler)))

    http.ListenAndServe(":8080", nil)
}

func userHandler(w http.ResponseWriter, r *http.Request) {
    user, _ := authmiddleware.GetAuthUser(r.Context())
    // Use user.UUID, user.Email, user.Permissions
}

func apiHandler(w http.ResponseWriter, r *http.Request) {
    project, _ := authmiddleware.GetProjectContext(r.Context())
    // Use project.TenantID, project.Scopes
}
```

### Using with Gin

```go
package main

import (
    "github.com/gin-gonic/gin"
    authmiddleware "github.com/wazobiatech/auth-middleware-go"
)

func main() {
    r := gin.Default()

    // JWT protected route
    r.GET("/user", authmiddleware.GinJWTMiddleware(), userHandler)

    // Project protected route
    r.GET("/api/data", authmiddleware.GinProjectMiddleware("my-service"), dataHandler)

    // With scope checking
    r.GET("/admin", 
        authmiddleware.GinProjectMiddleware("my-service"),
        authmiddleware.GinRequireScope("admin:read"),
        adminHandler,
    )

    r.Run(":8080")
}

func userHandler(c *gin.Context) {
    user, _ := authmiddleware.GinGetAuthUser(c)
    c.JSON(200, gin.H{"user": user})
}

func dataHandler(c *gin.Context) {
    project, _ := authmiddleware.GinGetProjectContext(c)
    c.JSON(200, gin.H{"project": project})
}
```

### Using with Echo

```go
package main

import (
    "github.com/labstack/echo/v4"
    authmiddleware "github.com/wazobiatech/auth-middleware-go"
)

func main() {
    e := echo.New()

    // JWT protected route
    e.GET("/user", userHandler, authmiddleware.EchoJWTMiddleware())

    // Project protected route
    e.GET("/api/data", dataHandler, authmiddleware.EchoProjectMiddleware("my-service"))

    // With scope checking
    e.GET("/admin", adminHandler, 
        authmiddleware.EchoProjectMiddleware("my-service"),
        authmiddleware.EchoRequireScope("admin:read"),
    )

    e.Start(":8080")
}
```

### Using with Fiber

```go
package main

import (
    "github.com/gofiber/fiber/v2"
    authmiddleware "github.com/wazobiatech/auth-middleware-go"
)

func main() {
    app := fiber.New()

    // JWT protected route
    app.Get("/user", authmiddleware.FiberJWTMiddleware(), userHandler)

    // Project protected route
    app.Get("/api/data", authmiddleware.FiberProjectMiddleware("my-service"), dataHandler)

    app.Listen(":8080")
}

func userHandler(c *fiber.Ctx) error {
    user, _ := authmiddleware.FiberGetAuthUser(c)
    return c.JSON(fiber.Map{"user": user})
}
```

### Using with Chi

```go
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    authmiddleware "github.com/wazobiatech/auth-middleware-go"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)

    // Protected routes
    r.Group(func(r chi.Router) {
        r.Use(authmiddleware.ChiProjectMiddleware("my-service"))
        r.Get("/api/data", dataHandler)
    })

    http.ListenAndServe(":8080", r)
}
```

## GraphQL Usage

```go
package main

import (
    "context"
    authmiddleware "github.com/wazobiatech/auth-middleware-go"
)

func main() {
    // Create auth helper
    authHelper := authmiddleware.NewAuthHelper("my-service")

    // Wrap resolvers
    resolvers := &Resolvers{
        Query: QueryResolver{
            Me: authHelper.WithUserAuth(meResolver, "profile:read"),
            Projects: authHelper.WithProjectAuth(projectsResolver, "projects:read"),
            AdminData: authHelper.WithCombinedAuth(adminResolver, 
                []string{"admin:read"},    // user scopes
                []string{"platform:read"}, // project scopes
            ),
        },
    }
}

func meResolver(ctx context.Context, args interface{}) (interface{}, error) {
    user, err := authmiddleware.GraphQLGetCurrentUser(ctx)
    if err != nil {
        return nil, err
    }
    return user, nil
}
```

## Token Types

### User Token (Authorization Header)

```
Authorization: Bearer <jwt_token>
```

Validated against JWKS from Mercury. Sets `AuthUser` in context with:
- UUID
- Email
- Name
- TenantID
- Permissions

### Project Token (x-project-token Header)

```
x-project-token: Bearer <project_token>
```

Validated for project access. Sets `ProjectContext` in context with:
- TenantID
- ProjectUUID
- EnabledServices
- Scopes
- SecretVersion

### Service Token (x-project-token Header)

```
x-project-token: Bearer <service_token>
```

For service-to-service communication. Sets `ServiceContext` in context with:
- ClientID
- ServiceName
- Scopes

### Platform Token (x-project-token Header)

```
x-project-token: Bearer <platform_token>
```

For platform-level access. Sets `PlatformContext` in context with:
- TenantID
- Scopes
- TokenID

## Scope Validation

Scopes can be validated using middleware:

```go
// Single scope
authmiddleware.RequireScope("users:read")

// Multiple scopes (all required)
authmiddleware.RequireScope("users:read", "users:write")

// For GraphQL
authHelper.WithUserAuth(resolver, "users:read", "users:write")
```

## Advanced Usage

### Custom Authentication

```go
jwtAuth := authmiddleware.NewJwtAuthMiddleware()
user, err := jwtAuth.Authenticate(r)
if err != nil {
    // Handle error
}

projectAuth := authmiddleware.NewProjectAuthMiddleware("my-service")
authReq, err := projectAuth.Authenticate(r)
if err != nil {
    // Handle error
}
```

### Optional Authentication

```go
// Optional JWT - continues if not authenticated
r.Use(authmiddleware.OptionalJWTMiddleware())

// Optional Project - continues if not authenticated
r.Use(authmiddleware.OptionalProjectMiddleware("my-service"))
```

### Service-to-Service Communication

```go
client := authmiddleware.NewServiceClient()
token, err := client.GenerateToken()
if err != nil {
    // Handle error
}

serviceID, err := client.GetServiceByID(token)
if err != nil {
    // Handle error
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Auth Middleware Library                       │
├─────────────────────────────────────────────────────────────────┤
│  Framework Adapters  │  GraphQL   │  Core Auth  │   Internal    │
│  ─────────────────   │  ───────   │  ─────────  │   ─────────   │
│  • Gin               │  Helpers   │  • JWT      │   • Config    │
│  • Echo              │  • With*   │  • Project  │   • Cache     │
│  • Fiber             │  • Get*    │  • Service  │   • Signature │
│  • Chi               │            │  • Platform │               │
│  • net/http          │            │             │               │
├─────────────────────────────────────────────────────────────────┤
│  External Dependencies                                         │
│  • Redis (caching)                                             │
│  • Mercury (auth service)                                      │
│  • JWKS (key management)                                       │
└─────────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run all tests
go test ./...

# Run with race detection
go test -race ./...

# Run benchmarks
go test -bench=. ./...
```

## License

MIT License

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
