package config

import (
	"os"
	"strconv"
	"sync"
)

// Config holds all configuration for the internal packages
type Config struct {
	MercuryBaseURL        string
	SignatureSharedSecret string
	RedisURL              string
	RedisPassword         string
	RedisDB               int
	ClientID              string
	ClientSecret          string
	ServiceTokenCacheTTL  int // seconds
	ServiceUUIDCacheTTL   int // seconds
	JWKSCacheTTL          int // seconds
	CacheExpiryTime       int // seconds
}

var (
	instance *Config
	once     sync.Once
)

// GetConfig returns the singleton configuration instance
func GetConfig() *Config {
	once.Do(func() {
		instance = loadConfig()
	})
	return instance
}

func loadConfig() *Config {
	return &Config{
		MercuryBaseURL:        getEnv("MERCURY_BASE_URL", "http://localhost:4000"),
		SignatureSharedSecret: getEnv("SIGNATURE_SHARED_SECRET", ""),
		RedisURL:              getEnv("REDIS_URL", "redis://localhost:6379"),
		RedisPassword:         getEnv("REDIS_PASSWORD", ""),
		RedisDB:               getEnvAsInt("REDIS_DB", 0),
		ClientID:              getEnv("CLIENT_ID", ""),
		ClientSecret:          getEnv("CLIENT_SECRET", ""),
		ServiceTokenCacheTTL:  getEnvAsInt("SERVICE_TOKEN_CACHE_TTL", 3300),  // ~55 mins
		ServiceUUIDCacheTTL:   getEnvAsInt("SERVICE_UUID_CACHE_TTL", 86400), // 24 hours
		JWKSCacheTTL:          getEnvAsInt("JWKS_CACHE_TTL", 18000),         // 5 hours
		CacheExpiryTime:       getEnvAsInt("CACHE_EXPIRY_TIME", 3600),       // 1 hour
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}
