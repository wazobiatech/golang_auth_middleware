package redis

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wazobiatech/golang_auth_middleware/pkg/utils"
)

// Client wraps Redis client with connection management and health checking
type Client struct {
	client      *redis.Client
	config      *utils.Config
	mutex       sync.RWMutex
	isConnected bool
}

var (
	instance *Client
	once     sync.Once
)

// NewClient creates a new Redis client instance using singleton pattern
func NewClient() *Client {
	once.Do(func() {
		config := utils.GetConfig()
		
		rdb := redis.NewClient(&redis.Options{
			Addr:         config.RedisURL,
			Password:     config.RedisPassword,
			DB:           config.RedisDB,
			PoolSize:     10,
			PoolTimeout:  30 * time.Second,
			DialTimeout:  10 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
			// Retry settings
			MaxRetries:      3,
			MinRetryBackoff: 8 * time.Millisecond,
			MaxRetryBackoff: 512 * time.Millisecond,
			// Connection pool settings
			ConnMaxIdleTime: 30 * minute,
			ConnMaxLifetime: time.Hour,
		})

		instance = &Client{
			client: rdb,
			config: config,
		}

		// Test connection
		ctx := context.Background()
		if err := instance.Ping(ctx); err != nil {
			log.Printf("Redis connection failed: %v", err)
		} else {
			instance.isConnected = true
			log.Println("Redis client connected successfully")
		}

		// Setup connection event handlers
		instance.setupEventHandlers()
	})

	return instance
}

// setupEventHandlers configures Redis connection event handlers
func (c *Client) setupEventHandlers() {
	// Redis go client doesn't have built-in event handlers like Node.js
	// We'll implement health checking through periodic pings
}

// Ping checks Redis connection health
func (c *Client) Ping(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	err := c.client.Ping(ctx).Err()
	c.mutex.Lock()
	c.isConnected = (err == nil)
	c.mutex.Unlock()

	if err != nil {
		log.Printf("Redis ping failed: %v", err)
	}

	return err
}

// IsConnected returns the current connection status
func (c *Client) IsConnected() bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.isConnected
}

// ensureConnected performs health check and reconnects if necessary
func (c *Client) ensureConnected() error {
	if c.IsConnected() {
		// Quick health check
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		
		if err := c.Ping(ctx); err == nil {
			return nil
		}
	}

	// Connection is down, attempt to reconnect
	log.Println("Redis connection is down, attempting to reconnect...")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	return c.Ping(ctx)
}

// Set stores a key-value pair in Redis with expiration
func (c *Client) Set(key, value string, expiration time.Duration) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.client.Set(ctx, key, value, expiration).Err()
}

// Get retrieves a value from Redis by key
func (c *Client) Get(key string) (string, error) {
	if err := c.ensureConnected(); err != nil {
		return "", fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result := c.client.Get(ctx, key)
	if result.Err() == redis.Nil {
		return "", fmt.Errorf("key not found")
	}

	return result.Result()
}

// Exists checks if a key exists in Redis
func (c *Client) Exists(key string) (bool, error) {
	if err := c.ensureConnected(); err != nil {
		return false, fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	count, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Del deletes a key from Redis
func (c *Client) Del(key string) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.client.Del(ctx, key).Err()
}

// SetEX sets a key with expiration in seconds
func (c *Client) SetEX(key, value string, seconds int) error {
	return c.Set(key, value, time.Duration(seconds)*time.Second)
}

// TTL returns the time to live for a key
func (c *Client) TTL(key string) (time.Duration, error) {
	if err := c.ensureConnected(); err != nil {
		return 0, fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.client.TTL(ctx, key).Result()
}

// Expire sets expiration for a key
func (c *Client) Expire(key string, expiration time.Duration) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.client.Expire(ctx, key, expiration).Err()
}

// HSet stores a hash field and value
func (c *Client) HSet(key, field, value string) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.client.HSet(ctx, key, field, value).Err()
}

// HGet retrieves a hash field value
func (c *Client) HGet(key, field string) (string, error) {
	if err := c.ensureConnected(); err != nil {
		return "", fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	result := c.client.HGet(ctx, key, field)
	if result.Err() == redis.Nil {
		return "", fmt.Errorf("field not found")
	}

	return result.Result()
}

// HExists checks if a hash field exists
func (c *Client) HExists(key, field string) (bool, error) {
	if err := c.ensureConnected(); err != nil {
		return false, fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.client.HExists(ctx, key, field).Result()
}

// HDel deletes hash fields
func (c *Client) HDel(key string, fields ...string) error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	return c.client.HDel(ctx, key, fields...).Err()
}

// Keys returns keys matching a pattern
func (c *Client) Keys(pattern string) ([]string, error) {
	if err := c.ensureConnected(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return c.client.Keys(ctx, pattern).Result()
}

// FlushDB flushes the current database
func (c *Client) FlushDB() error {
	if err := c.ensureConnected(); err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return c.client.FlushDB(ctx).Err()
}

// Pipeline creates a new pipeline for batch operations
func (c *Client) Pipeline() redis.Pipeliner {
	return c.client.Pipeline()
}

// TxPipeline creates a new transaction pipeline
func (c *Client) TxPipeline() redis.Pipeliner {
	return c.client.TxPipeline()
}

// Close closes the Redis connection
func (c *Client) Close() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.client != nil {
		err := c.client.Close()
		c.isConnected = false
		log.Println("Redis connection closed")
		return err
	}

	return nil
}

// Stats returns Redis connection statistics
func (c *Client) Stats() *redis.PoolStats {
	if c.client != nil {
		return c.client.PoolStats()
	}
	return nil
}

// Config returns the Redis configuration
func (c *Client) Config() *utils.Config {
	return c.config
}

// GetClient returns the underlying Redis client for advanced operations
func (c *Client) GetClient() *redis.Client {
	return c.client
}

// HealthCheck performs a comprehensive health check
func (c *Client) HealthCheck() error {
	// Basic connectivity test
	if err := c.Ping(context.Background()); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Test basic operations
	testKey := fmt.Sprintf("health_check_%d", time.Now().UnixNano())
	testValue := "ok"

	// Test SET
	if err := c.Set(testKey, testValue, time.Minute); err != nil {
		return fmt.Errorf("SET operation failed: %w", err)
	}

	// Test GET
	if value, err := c.Get(testKey); err != nil {
		return fmt.Errorf("GET operation failed: %w", err)
	} else if value != testValue {
		return fmt.Errorf("GET returned wrong value: expected %s, got %s", testValue, value)
	}

	// Test DEL
	if err := c.Del(testKey); err != nil {
		return fmt.Errorf("DEL operation failed: %w", err)
	}

	return nil
}

// Minute constant for better readability
const minute = time.Minute