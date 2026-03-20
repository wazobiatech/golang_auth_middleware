# Testing Guide for Go Auth Middleware

This directory contains comprehensive tests for the auth middleware library.

## Test Structure

```
tests/
├── unit/                    # Unit tests for individual components
│   ├── jwt_guard_test.go   # JWT authentication tests
│   ├── project_guard_test.go # Project auth tests
│   ├── framework_adapters_test.go # Framework adapter tests
│   └── graphql_helpers_test.go # GraphQL helper tests
├── integration/            # Integration tests
│   └── auth_flow_test.go  # End-to-end auth flow tests
├── example_usage_test.go   # Comprehensive usage examples
└── README.md              # This file
```

## Running Tests

### Run all tests
```bash
go test ./tests/...
```

### Run with verbose output
```bash
go test -v ./tests/...
```

### Run only unit tests
```bash
go test -v ./tests/unit/...
```

### Run only integration tests
```bash
go test -v ./tests/integration/...
```

### Run with race detection
```bash
go test -race ./tests/...
```

### Run benchmarks
```bash
go test -bench=. ./tests/...
```

### Run with coverage
```bash
go test -cover ./tests/...
go test -coverprofile=coverage.out ./tests/...
go tool cover -html=coverage.out
```

### Run in short mode (skip integration tests)
```bash
go test -short ./tests/...
```

## Test Categories

### 1. JWT Guard Tests (`unit/jwt_guard_test.go`)

Tests JWT authentication including:
- Token extraction from headers
- Missing/invalid token handling
- Token validation
- Mock JWKS server integration
- Claims validation

**Key test cases:**
- Missing authorization header
- Empty token
- Invalid token format
- Token validation with mock keys
- Claims validation (expiry, subject, issuer)

### 2. Project Guard Tests (`unit/project_guard_test.go`)

Tests project/platform/service token authentication:
- Token extraction from x-project-token header
- Service enablement checks
- Secret version validation
- Token type routing

**Key test cases:**
- Missing project token
- Service enablement verification
- Token type detection (platform, project, service)
- Cache TTL configuration

### 3. Framework Adapter Tests (`unit/framework_adapters_test.go`)

Tests framework-specific middleware:
- Gin middleware integration
- Context value extraction
- Scope validation middleware
- Optional authentication middleware

**Key test cases:**
- JWT middleware with Gin
- Project middleware with Gin
- Scope validation
- Context helper functions
- MustGet functions panic behavior

### 4. GraphQL Helper Tests (`unit/graphql_helpers_test.go`)

Tests GraphQL-specific helpers:
- Context key uniqueness
- Authentication wrappers
- Context value extraction
- Combined auth scenarios

**Key test cases:**
- User context extraction
- Project context extraction
- Service context extraction
- Platform context extraction
- HTTP request in context
- Scope checking logic

### 5. Integration Tests (`integration/auth_flow_test.go`)

End-to-end tests including:
- Complete authentication flows
- Context propagation
- Error handling
- Token type handling
- Scope validation flows

**Key test cases:**
- Full Gin middleware chain
- GraphQL context flow
- Scope validation end-to-end
- Error response formatting
- Context propagation through middleware

### 6. Example Usage Tests (`example_usage_test.go`)

Comprehensive examples showing:
- How to test JWT authentication
- How to test project authentication
- How to test scope validation
- How to test GraphQL resolvers
- How to mock the middleware
- How to test different token types
- Complete integration scenarios

## Writing Your Own Tests

### Basic Test Structure

```go
func TestYourFeature(t *testing.T) {
    // Setup
    gin.SetMode(gin.TestMode)
    router := gin.New()
    router.Use(authmiddleware.GinJWTMiddleware())
    router.GET("/test", handler)

    // Execute
    req := httptest.NewRequest("GET", "/test", nil)
    req.Header.Set("Authorization", "Bearer token")
    w := httptest.NewRecorder()
    router.ServeHTTP(w, req)

    // Assert
    if w.Code != http.StatusOK {
        t.Errorf("Expected %d, got %d", http.StatusOK, w.Code)
    }
}
```

### Mocking the Middleware

```go
type MockAuthMiddleware struct {
    AuthenticateUserFunc func(r *http.Request) (*types.AuthUser, error)
}

func (m *MockAuthMiddleware) AuthenticateUser(r *http.Request) (*types.AuthUser, error) {
    if m.AuthenticateUserFunc != nil {
        return m.AuthenticateUserFunc(r)
    }
    return nil, types.NewAuthError(types.ErrCodeInvalidToken, "mock error")
}

// Usage in test
mock := &MockAuthMiddleware{
    AuthenticateUserFunc: func(r *http.Request) (*types.AuthUser, error) {
        return &types.AuthUser{
            UUID: "test-uuid",
            Email: "test@example.com",
        }, nil
    },
}
```

### Testing GraphQL Resolvers

```go
func TestGraphQLResolver(t *testing.T) {
    // Setup context with auth data
    ctx := context.Background()
    user := &types.AuthUser{
        UUID: "user-123",
        Permissions: []string{"read"},
    }
    ctx = context.WithValue(ctx, graphql.UserKey, user)

    // Test resolver
    result, err := yourResolver(ctx, args)
    
    // Assert
    if err != nil {
        t.Errorf("Unexpected error: %v", err)
    }
}
```

### Testing Scope Validation

```go
func TestScopeValidation(t *testing.T) {
    provided := []string{"read", "write", "admin"}
    required := []string{"read", "write"}

    scopeSet := make(map[string]bool)
    for _, s := range provided {
        scopeSet[s] = true
    }

    passes := true
    for _, r := range required {
        if !scopeSet[r] {
            passes = false
            break
        }
    }

    if !passes {
        t.Error("Scope validation failed")
    }
}
```

## Environment Setup for Testing

### Required Environment Variables

```bash
export MERCURY_BASE_URL=http://localhost:4000
export REDIS_URL=redis://localhost:6379
export CLIENT_ID=test-client
export CLIENT_SECRET=test-secret
export SIGNATURE_SHARED_SECRET=test-signature
```

### Using dotenv for Tests

Create a `.env.test` file:

```
MERCURY_BASE_URL=http://localhost:4000
REDIS_URL=redis://localhost:6379
CLIENT_ID=test-client
CLIENT_SECRET=test-secret
SIGNATURE_SHARED_SECRET=test-signature
CACHE_EXPIRY_TIME=3600
JWKS_CACHE_TTL=18000
```

## Test Data

### Valid JWT Token Structure

```json
{
  "sub": {
    "uuid": "user-uuid",
    "email": "user@example.com",
    "name": "User Name"
  },
  "tenant_id": "tenant-123",
  "permissions": ["read", "write"],
  "type": "user",
  "iss": "https://mercury.example.com",
  "aud": "https://api.example.com",
  "exp": 1234567890,
  "nbf": 1234567800,
  "iat": 1234567800,
  "jti": "token-id"
}
```

### Valid Project Token Structure

```json
{
  "tenant_id": "tenant-123",
  "secret_version": 1,
  "enabled_services": ["service-1", "service-2"],
  "token_id": "token-123",
  "type": "project",
  "scopes": ["read", "write"],
  "iss": "https://mercury.example.com",
  "aud": "https://api.example.com",
  "exp": 1234567890,
  "nbf": 1234567800,
  "iat": 1234567800
}
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      redis:
        image: redis
        ports:
          - 6379:6379
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Run tests
      run: go test -v -race -coverprofile=coverage.out ./tests/...
      env:
        MERCURY_BASE_URL: http://localhost:4000
        REDIS_URL: redis://localhost:6379
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
```

## Debugging Tests

### Enable Debug Logging

```go
func init() {
    // Set log level for tests
    os.Setenv("LOG_LEVEL", "debug")
}
```

### Print Request/Response

```go
func TestWithDebug(t *testing.T) {
    // ... setup ...
    
    router.ServeHTTP(w, req)
    
    t.Logf("Request: %+v", req)
    t.Logf("Response Status: %d", w.Code)
    t.Logf("Response Body: %s", w.Body.String())
}
```

## Common Issues

### 1. "Redis connection refused"

Make sure Redis is running or mock the Redis client in tests.

### 2. "JWKS endpoint not reachable"

Use mock servers or set `MERCURY_BASE_URL` to a mock URL.

### 3. Race conditions

Run with `-race` flag and fix any detected races.

### 4. Context deadline exceeded

Increase timeout values or use `go test -timeout 30s`.

## Best Practices

1. **Use table-driven tests** for multiple test cases
2. **Mock external dependencies** (Redis, Mercury)
3. **Test error cases** as thoroughly as success cases
4. **Use short mode** to skip slow integration tests during development
5. **Clean up resources** after tests
6. **Use parallel tests** where possible: `t.Parallel()`
7. **Document test purpose** with clear test names
