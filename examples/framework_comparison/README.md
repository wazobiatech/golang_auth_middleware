# Framework Integration Examples

This directory contains examples showing how to integrate the auth middleware with different Go web frameworks.

## Available Examples:

1. **`standalone_user_auth/`** - Standard `net/http` library with JWT authentication
2. **`gin_with_scopes/`** - Gin framework with scope-based authorization
3. **`graphql_integration/`** - GraphQL server with authentication context
4. **`service_to_service/`** - Service-to-service authentication using client credentials

## Quick Comparison

### Standard Library (net/http)
```go
jwtAuth := auth.NewJwtAuthMiddleware()
user, err := jwtAuth.Authenticate(r)
```

### Gin Framework
```go
r.Use(authGin.JWTMiddleware())
r.Use(authGin.ProjectMiddleware("service-name"))
```

### GraphQL Context
```go
type GraphQLContext struct {
    User *types.AuthUser
    Project *types.ProjectContext
    // ...
}
```

### Service Client
```go
serviceClient := client.NewServiceClient()
token, err := serviceClient.GenerateToken()
```

## Environment Variables

All examples use the same environment variables:

```bash
# Required
-export REDIS_URL=redis://localhost:6379
export MERCURY_BASE_URL=http://localhost:4000
export SIGNATURE_SHARED_SECRET=your-shared-secret

# For service auth
export CLIENT_ID=your-service-client-id
export CLIENT_SECRET=your-service-client-secret

# Optional
export CACHE_EXPIRY_TIME=3600
export JWKS_CACHE_TTL=18000
export LOG_LEVEL=info
```

## Running the Examples

Each example has its own `main.go` file. To run:

```bash
cd standalone_user_auth
go run main.go

cd gin_with_scopes
go run main.go

# etc.
```