# Testing Plan for Go Auth Middleware Replication

## Current Testing Status

**Status: UNTESTED** ❌

The Go implementation has been meticulously crafted by reading and analyzing the Node.js source code, but **NO CODE HAS BEEN RUN OR TESTED**. This document provides a comprehensive testing plan.

---

## 1. Manual Testing Checklist

### Step 1: Environment Setup
```bash
cd /Users/ram/Documents/tech projects/wazobia tech/golang_auth_middleware

# Ensure .env is present
ls -la .env

# Verify environment variables
cat .env | grep -E "(MERCURY_BASE_URL|REDIS_URL|CLIENT_ID)"
```
**✅ Expected:** All variables configured properly

### Step 2: Build Test
```bash
go mod tidy
go mod download
go build ./...
go test ./... -v
```
**✅ Expected:** Clean build, no compilation errors

### Step 3: Unit Tests Run
```bash
cd pkg/auth
go test -v -run TestJwtAuthMiddleware_Authenticate
go test -v -run TestProjectAuthMiddleware_Authenticate

# Or run all tests
go test ./... -v -cover
```
**❌ Status:** Tests were created but NOT run. Need to verify they compile and pass.

### Step 4: Integration Test with Real Token
```bash
cd examples/debug-token
go run main.go $MERCURY_PROJECT_TOKEN
```
**Expected Output:**
- ✅ Header decoded
- ✅ Payload decoded
- ✅ User UUID extracted
- ✅ Permissions array visible
- ✅ Token type identified

**Test Token:** Use actual token from:
```bash
echo $MERCURY_PROJECT_TOKEN  # From iris/.env
```

### Step 5: Redis Connection Test
```bash
cd test
go test -v -run TestRedisIntegration
```
**Expected:** Connection to Redis at `51.222.28.24:32558` succeeds

### Step 6: Platform Token Verification Test
```bash
cd examples/platform_and_service_verification
go run main.go &
sleep 2

curl -X POST http://localhost:8080/api/validate-token \
  -H "Content-Type: application/json" \
  -H "x-project-token: Bearer $MERCURY_PROJECT_TOKEN" \
  -d '{}'
```

**Expected Response:**
```json
{
  "valid": true,
  "token_type": "project",
  "project": {
    "tenant_id": "0af8cd66-72ad-45c4-92e2-3059cf643213",
    "scopes": [...]
  }
}
```

---

## 2. Automated Testing Strategy

### Unit Tests (Created but not run)
```go
// pkg/auth/jwt_guard_test.go
func TestJwtAuthMiddleware_Authenticate(t *testing.T)
func TestProjectAuthMiddleware_Authenticate(t *testing.T)

// Test coverage needed:
- Valid token with all claims
- Expired token
- Invalid signature
- Missing kid in header
- Invalid issuer
- Invalid audience
- Token with no permissions
- Token with many permissions
- Revoked token (Redis check)
```

### Integration Tests (Template created)
```go
// test/integration_test.go
func TestJWTAuthenticationFlow(t *testing.T)
func TestRedisIntegration(t *testing.T)
func TestServiceTokenGeneration(t *testing.T)
```

**To run all tests:**
```bash
go test ./pkg/... -v -cover
go test ./test/... -v
```

### Example-Based Testing
```bash
# Test each example
cd examples/debug-token
go run main.go $MERCURY_PROJECT_TOKEN

cd examples/platform_and_service_verification
go run main.go
# Test endpoints with real tokens

cd examples/standalone_user_auth
go run main.go

# Test service auth
cd examples/service_to_service
go run main.go
```

---

## 3. Critical Validation Points

### 3.1 JWT Token Extraction ✅ Implemented
**Node.js:**
```typescript
const token = authHeader.startsWith('Bearer ')
  ? authHeader.slice(7)
  : authHeader;
```

**Go:**
```go
var token string
if strings.HasPrefix(authHeader, "Bearer ") {
    token = strings.TrimPrefix(authHeader, "Bearer ")
} else {
    token = authHeader
}
```

**How to test:**
```bash
curl -H "Authorization: Bearer eyJ..." http://localhost:8080/api/test
curl -H "Authorization: eyJ..." http://localhost:8080/api/test  # Without "Bearer"
```

### 3.2 Tenant ID Extraction ✅ Implemented
**Node.js:** `decodeJWTTokenForTenantId()`
**Go:** `decodeJWTTokenForTenantId()`

**How to test:**
```bash
# Token should have tenant_id in payload
# Use debug-token utility to verify extraction
go run examples/debug-token/main.go $TOKEN
```

### 3.3 JWKS URI Construction ✅ Implemented
**Node.js:** `auth/projects/{tenant_id}/.well-known/jwks.json`
**Go:** Same pattern

**How to test:**
```bash
# Check logs for JWKS URI construction
# Should see: "https://mercury.tiadara.com/auth/projects/{tenant_id}/.well-known/jwks.json"
```

### 3.4 Redis Token Caching ✅ Implemented
**Node.js:** `validated_token:{hash}` with TTL
**Go:** Same pattern

**How to test:**
```bash
# Use redis-cli to check cache
redis-cli -u redis://default:wazobia@51.222.28.24:32558/0
KEYS validated_token:*
TTL validated_token:xxxx
```

### 3.5 Service Token Generation ✅ Implemented
**Node.js:** GraphQL mutation to Mercury
**Go:** Same GraphQL mutation

**How to test:**
```bash
cd examples/service_to_service
go run main.go

# Should output:
# Service token generated successfully
# Token prefix: eyJ...
# Service UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

### 3.6 Scope Validation ✅ Implemented
**Node.js:** `scopes.includes(requiredScope)`
**Go:** Iterates and checks scopes

**How to test:**
```bash
# Call endpoint requiring specific scope
curl -H "x-project-token: Bearer $TOKEN" \
     http://localhost:8080/api/scoped-endpoint

# Should succeed if token has scope
# Should fail 403 if token lacks scope
```

### 3.7 Platform Token Handling ✅ Implemented
**Test platform-only endpoints:**
```bash
curl -H "x-project-token: Bearer $PLATFORM_TOKEN" \
     http://localhost:8080/api/platform/admin/users

# Should work with platform token
# Should fail with project token
```

---

## 4. Real-World Testing with Iris

### Integration Test with Iris Service
```bash
# Start golang_auth_middleware service
cd examples/platform_and_service_verification
go run main.go &

# In another terminal, test against Iris
export IRIS_TOKEN=$MERCURY_PROJECT_TOKEN

curl -H "x-project-token: Bearer $IRIS_TOKEN" \
     http://localhost:8080/api/platform/admin/users

# Then call actual Iris endpoint
export IRIS_URL=https://iris.tiadara.com

curl -H "x-project-token: Bearer $IRIS_TOKEN" \
     $IRIS_URL/api/some-protected-endpoint
```

### Compare with Node.js Auth Middleware
```bash
# Test Node.js version
cd node_auth_middleware
npm run test
cd examples
time node express-example.js

# Test Go version
cd golang_auth_middleware/examples/platform_and_service_verification
time go run main.go

# Compare response times, memory usage, token validation
```

---

## 5. Testing Commands Summary

```bash
# All-in-one test command
cd /Users/ram/Documents/tech projects/wazobia tech/golang_auth_middleware

# 1. Build test
go build ./...

# 2. Unit tests
go test ./pkg/... -v -cover

# 3. Print actual token for testing
echo "Token: $MERCURY_PROJECT_TOKEN"
echo "Token prefix: ${MERCURY_PROJECT_TOKEN:0:50}..."

# 4. Debug token
cd examples/debug-token
go run main.go "$MERCURY_PROJECT_TOKEN"

# 5. Run integration test with real token
cd examples/platform_and_service_verification
go run main.go &
PID=$!
sleep 3

echo "Testing platform endpoint..."
curl -s -H "x-project-token: Bearer $MERCURY_PROJECT_TOKEN" \
     http://localhost:8080/api/validate-token

echo ""
echo "Testing multi-token validation..."
curl -s -X POST -H "Content-Type: application/json" \
     -H "x-project-token: Bearer $MERCURY_PROJECT_TOKEN" \
     -d '{}' \
     http://localhost:8080/api/validate-token

kill $PID

# 6. Redis check
echo "Redis connection test..."
redis-cli -u redis://default:wazobia@51.222.28.24:32558/0 ping
```

---

## 6. Known Areas That Need Testing

### Critical (Must Test)
1. ✅ JWT RSA signature verification - Need real private/public key pair
2. ✅ JWKS endpoint fetching - Need Mercury to be running
3. ✅ Redis token caching - Need Redis connection
4. ✅ Token revocation check - Need to set revocation in Redis
5. ✅ Scope validation - Need tokens with various scopes
6. ✅ Project service enablement check - Need service UUID from Mercury

### Important (Should Test)
1. Concurrent request handling
2. Redis connection failure fallback
3. JWKS cache expiry and refresh
4. Service token caching (55 min TTL)
5. Error response formats
6. Logging output

### Nice to Have (Optional)
1. Performance benchmarks vs Node.js
2. Memory usage comparison
3. Token parsing speed
4. Redis operation latency

---

## 7. Test Results Template

Create this file after testing:
`TEST_RESULTS.md`

```markdown
# Test Results - Go Auth Middleware

Date: [Date]
Tester: [Name]

## Build Status
- [ ] Clean build
- [ ] All dependencies resolved
- [ ] No compilation errors

## Unit Tests
- JWT tests: [X/Y passed]
- Project tests: [X/Y passed]
- Redis tests: [X/Y passed]
- Total coverage: [XX]%

## Integration Tests
- Real token validation: [PASS/FAIL]
- Platform token flow: [PASS/FAIL]
- User token flow: [PASS/FAIL]
- Service token flow: [PASS/FAIL]
- Token caching: [PASS/FAIL]
- Revocation check: [PASS/FAIL]

## Issues Found
1. [Issue description]
2. [Issue description]

## Comparison with Node.js
- Performance: Go is [X%] faster/slower
- Memory: Go uses [X%] more/less memory
- Response time: [Comparison]

## Conclusion
[Ready for production / Needs fixes / More testing required]
```

---

## 8. Next Steps

1. **Run unit tests**: `go test ./...`
2. **Fix any compilation errors**
3. **Debug token utility**: Test with real token
4. **Redis connection test**: Verify connectivity
5. **Integration testing**: Run examples
6. **Compare with Node.js**: Verify behavior matches
7. **Production readiness**: Document any discrepancies

## Summary

**Current State:** Code written but NOT tested
**Risk Level:** HIGH (untested authentication code)
**Action Required:** Run all tests above before production use

The implementation was based on careful code analysis of the Node.js version, but authentication code **must be tested** with real tokens and real Mercury service before deployment.