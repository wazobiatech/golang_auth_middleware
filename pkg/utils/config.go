package utils

import (
	"log"
	"os"
	"strconv"
	"sync"
)

// Config holds all configuration values for the authentication middleware
type Config struct {
	// Mercury service configuration
	MercuryBaseURL          string
	SignatureSharedSecret   string
	
	// Redis configuration
	RedisURL      string
	RedisPassword string
	RedisDB       int
	
	// Service credentials
	ClientID     string
	ClientSecret string
	
	// Cache configuration
	CacheExpiryTime int // seconds
	
	// JWT configuration
	JWKSCacheTTL int // seconds
	
	// Logging configuration
	LogLevel string
}

var (
	config *Config
	configOnce sync.Once
)

// GetConfig returns the singleton configuration instance
func GetConfig() *Config {
	configOnce.Do(func() {
		config = loadConfig()
	})
	return config
}

// loadConfig loads configuration from environment variables
func loadConfig() *Config {
	cfg := &Config{
		// Mercury service configuration
		MercuryBaseURL:        getEnv("MERCURY_BASE_URL", "http://localhost:4000"),
		SignatureSharedSecret: getEnv("SIGNATURE_SHARED_SECRET", ""),

		// Redis configuration — prefer AUTH_REDIS_* to avoid conflicts with app Redis
		RedisURL:      getEnvFallback("AUTH_REDIS_HOST", "REDIS_URL", "localhost:6379"),
		RedisPassword: getEnvFallback("AUTH_REDIS_PASSWORD", "REDIS_PASSWORD", ""),
		RedisDB:       getEnvAsInt("AUTH_REDIS_DB", getEnvAsInt("REDIS_DB", 0)),

		// Service credentials
		ClientID:     getEnv("CLIENT_ID", ""),
		ClientSecret: getEnv("CLIENT_SECRET", ""),

		// Cache configuration
		CacheExpiryTime: getEnvAsInt("CACHE_EXPIRY_TIME", 3600), // 1 hour default

		// JWT configuration
		JWKSCacheTTL: getEnvAsInt("JWKS_CACHE_TTL", 18000), // 5 hours default

		// Logging configuration
		LogLevel: getEnv("LOG_LEVEL", "info"),
	}

	// Validate required configuration
	validateConfig(cfg)

	return cfg
}

// validateConfig ensures required configuration values are present
func validateConfig(cfg *Config) {
	if cfg.MercuryBaseURL == "" {
		log.Println("Warning: MERCURY_BASE_URL is not set, using default")
	}
	
	if cfg.SignatureSharedSecret == "" {
		log.Println("Warning: SIGNATURE_SHARED_SECRET is not set")
	}
	
	if cfg.RedisURL == "" {
		log.Println("Warning: REDIS_URL is not set, using default")
	}
	
	if cfg.ClientID == "" {
		log.Println("Warning: CLIENT_ID is not set")
	}
	
	if cfg.ClientSecret == "" {
		log.Println("Warning: CLIENT_SECRET is not set")
	}
}

// getEnvFallback returns the first non-empty env var, falling back to defaultValue
func getEnvFallback(primary, secondary, defaultValue string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	if v := os.Getenv(secondary); v != "" {
		return v
	}
	return defaultValue
}

// getEnv gets environment variable with a default fallback
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvAsInt gets environment variable as integer with a default fallback
func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		log.Printf("Warning: Invalid integer value for %s: %s, using default %d", key, valueStr, defaultValue)
		return defaultValue
	}

	return value
}

// getEnvAsBool gets environment variable as boolean with a default fallback
func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		log.Printf("Warning: Invalid boolean value for %s: %s, using default %t", key, valueStr, defaultValue)
		return defaultValue
	}

	return value
}

// UpdateConfig allows runtime configuration updates
func UpdateConfig(updates map[string]interface{}) {
	if config == nil {
		config = GetConfig()
	}

	for key, value := range updates {
		switch key {
		case "MERCURY_BASE_URL":
			if v, ok := value.(string); ok {
				config.MercuryBaseURL = v
			}
		case "SIGNATURE_SHARED_SECRET":
			if v, ok := value.(string); ok {
				config.SignatureSharedSecret = v
			}
		case "REDIS_URL":
			if v, ok := value.(string); ok {
				config.RedisURL = v
			}
		case "REDIS_PASSWORD":
			if v, ok := value.(string); ok {
				config.RedisPassword = v
			}
		case "REDIS_DB":
			if v, ok := value.(int); ok {
				config.RedisDB = v
			}
		case "CLIENT_ID":
			if v, ok := value.(string); ok {
				config.ClientID = v
			}
		case "CLIENT_SECRET":
			if v, ok := value.(string); ok {
				config.ClientSecret = v
			}
		case "CACHE_EXPIRY_TIME":
			if v, ok := value.(int); ok {
				config.CacheExpiryTime = v
			}
		case "JWKS_CACHE_TTL":
			if v, ok := value.(int); ok {
				config.JWKSCacheTTL = v
			}
		case "LOG_LEVEL":
			if v, ok := value.(string); ok {
				config.LogLevel = v
			}
		}
	}
}

// PrintConfig prints the current configuration (excluding secrets)
func PrintConfig() {
	log.Println("Auth Middleware Configuration:")
	log.Printf("  MERCURY_BASE_URL: %s", config.MercuryBaseURL)
	log.Printf("  REDIS_URL: %s", config.RedisURL)
	log.Printf("  REDIS_DB: %d", config.RedisDB)
	log.Printf("  CLIENT_ID: %s", maskSecret(config.ClientID))
	log.Printf("  CACHE_EXPIRY_TIME: %d seconds", config.CacheExpiryTime)
	log.Printf("  JWKS_CACHE_TTL: %d seconds", config.JWKSCacheTTL)
	log.Printf("  LOG_LEVEL: %s", config.LogLevel)
}

// maskSecret masks a secret value for logging
func maskSecret(secret string) string {
	if secret == "" {
		return "[not set]"
	}
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:2] + "****" + secret[len(secret)-2:]
}