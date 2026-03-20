package cache

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/wazobiatech/auth-middleware-go/internal/config"
	"github.com/wazobiatech/auth-middleware-go/pkg/redis"
)

// Cache provides caching functionality using Redis
type Cache struct {
	client *redis.Client
	config *config.Config
}

// NewCache creates a new cache instance
func NewCache() *Cache {
	return &Cache{
		client: redis.NewClient(),
		config: config.GetConfig(),
	}
}

// Set stores a value in cache with the given expiration
func (c *Cache) Set(key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal cache value: %w", err)
	}
	return c.client.Set(key, string(data), expiration)
}

// Get retrieves a value from cache
func (c *Cache) Get(key string, dest interface{}) error {
	data, err := c.client.Get(key)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(data), dest)
}

// Delete removes a key from cache
func (c *Cache) Delete(key string) error {
	return c.client.Del(key)
}

// Exists checks if a key exists in cache
func (c *Cache) Exists(key string) (bool, error) {
	return c.client.Exists(key)
}

// GetServiceTokenKey returns the cache key for service token
func (c *Cache) GetServiceTokenKey(clientID string) string {
	return fmt.Sprintf("service_token:%s", clientID)
}

// GetServiceUUIDKey returns the cache key for service UUID
func (c *Cache) GetServiceUUIDKey(clientID string) string {
	return fmt.Sprintf("service_uuid:%s", clientID)
}

// GetJWKSCacheKey returns the cache key for JWKS
func (c *Cache) GetJWKSCacheKey(tenantID string) string {
	return fmt.Sprintf("jwks_cache:%s", tenantID)
}

// GetServiceJWKSCacheKey returns the cache key for service JWKS
func (c *Cache) GetServiceJWKSCacheKey() string {
	return "service_jwks_cache"
}

// GetSecretVersionKey returns the cache key for tenant secret version
func (c *Cache) GetSecretVersionKey(tenantID string) string {
	return fmt.Sprintf("tenant_secret_version:%s", tenantID)
}

// GetTokenKey returns the cache key for platform/project token
func (c *Cache) GetTokenKey(tokenType, tokenID string) string {
	return fmt.Sprintf("%s_token:%s", tokenType, tokenID)
}

// GetRevocationKey returns the cache key for revoked token
func (c *Cache) GetRevocationKey(jti string) string {
	return fmt.Sprintf("revoked_token:%s", jti)
}
