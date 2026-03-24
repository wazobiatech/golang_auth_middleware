package jwks

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/wazobiatech/golang_auth_middleware/pkg/utils"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key Type
	Use string `json:"use"` // Public Key Use
	Kid string `json:"kid"` // Key ID
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Alg string `json:"alg"` // Algorithm
	X5c []string `json:"x5c,omitempty"` // X.509 Certificate Chain
}

// JWKSet represents a set of JSON Web Keys
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// KeyStore manages a set of JWKs and provides key lookup
type KeyStore struct {
	keys    map[string]*rsa.PublicKey
	rawKeys map[string]JWK
	mutex   sync.RWMutex
}

// NewKeyStore creates a new KeyStore instance
func NewKeyStore() *KeyStore {
	return &KeyStore{
		keys:    make(map[string]*rsa.PublicKey),
		rawKeys: make(map[string]JWK),
	}
}

// LoadFromJWKSet loads keys from a JWK set
func (ks *KeyStore) LoadFromJWKSet(jwkSet *JWKSet) error {
	ks.mutex.Lock()
	defer ks.mutex.Unlock()

	for _, jwk := range jwkSet.Keys {
		if jwk.Kty != "RSA" {
			continue // Skip non-RSA keys
		}

		publicKey, err := jwk.RSAPublicKey()
		if err != nil {
			log.Printf("Failed to convert JWK to RSA public key for kid %s: %v", jwk.Kid, err)
			continue
		}

		ks.keys[jwk.Kid] = publicKey
		ks.rawKeys[jwk.Kid] = jwk
	}

	return nil
}

// GetPublicKey retrieves a public key by its ID
func (ks *KeyStore) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	key, exists := ks.keys[kid]
	if !exists {
		return nil, fmt.Errorf("key with id %s not found", kid)
	}

	return key, nil
}

// GetJWK retrieves a raw JWK by its ID
func (ks *KeyStore) GetJWK(kid string) (*JWK, error) {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	jwk, exists := ks.rawKeys[kid]
	if !exists {
		return nil, fmt.Errorf("JWK with id %s not found", kid)
	}

	return &jwk, nil
}

// ListKids returns all available key IDs
func (ks *KeyStore) ListKids() []string {
	ks.mutex.RLock()
	defer ks.mutex.RUnlock()

	kids := make([]string, 0, len(ks.keys))
	for kid := range ks.keys {
		kids = append(kids, kid)
	}
	return kids
}

// RSAPublicKey converts JWK to RSA public key
func (jwk *JWK) RSAPublicKey() (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("key type %s not supported", jwk.Kty)
	}

	// Decode the modulus (n) and exponent (e) from base64url
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big integers
	var n, e big.Int
	n.SetBytes(nBytes)
	e.SetBytes(eBytes)

	// Validate exponent is within int range
	if !e.IsInt64() || e.Int64() > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("exponent too large")
	}

	return &rsa.PublicKey{
		N: &n,
		E: int(e.Int64()),
	}, nil
}

// Cache manages JWKS caching with automatic expiry and refresh
type Cache struct {
	entries map[string]*CacheEntry
	mutex   sync.RWMutex
	client  *http.Client
}

// CacheEntry represents a cached JWKS entry
type CacheEntry struct {
	KeyStore  *KeyStore
	ExpiresAt time.Time
	mutex     sync.RWMutex
}

// NewCache creates a new JWKS cache instance
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]*CacheEntry),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetOrFetch retrieves JWKS from cache or fetches from remote if expired/missing
func (c *Cache) GetOrFetch(cacheKey, jwksUri, path string) (*KeyStore, error) {
	c.mutex.RLock()
	entry, exists := c.entries[cacheKey]
	c.mutex.RUnlock()

	if exists {
		entry.mutex.RLock()
		expired := time.Now().After(entry.ExpiresAt)
		keyStore := entry.KeyStore
		entry.mutex.RUnlock()

		if !expired {
			log.Println("Using cached JWKS")
			return keyStore, nil
		}
	}

	log.Printf("Fetching JWKS from %s", jwksUri)

	// Fetch fresh JWKS
	keyStore, err := c.fetchAndCache(jwksUri, path, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return keyStore, nil
}

// fetchAndCache fetches JWKS from remote endpoint and caches it
func (c *Cache) fetchAndCache(jwksUri, path, cacheKey string) (*KeyStore, error) {
	// Create signed request
	req, err := c.createSignedRequest(jwksUri, path)
	if err != nil {
		return nil, fmt.Errorf("failed to create signed request: %w", err)
	}

	// Make HTTP request
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Parse JWKS response
	var jwksResponse struct {
		Keys interface{} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwksResponse); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS response: %w", err)
	}

	if jwksResponse.Keys == nil {
		return nil, fmt.Errorf("invalid JWKS response: missing keys")
	}

	// Handle both single key and key array
	var jwkSet JWKSet
	switch keys := jwksResponse.Keys.(type) {
	case []interface{}:
		jwkBytes, err := json.Marshal(map[string]interface{}{"keys": keys})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal keys array: %w", err)
		}
		if err := json.Unmarshal(jwkBytes, &jwkSet); err != nil {
			return nil, fmt.Errorf("failed to unmarshal JWK set: %w", err)
		}
	case map[string]interface{}:
		jwkBytes, err := json.Marshal(map[string]interface{}{"keys": []interface{}{keys}})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal single key: %w", err)
		}
		if err := json.Unmarshal(jwkBytes, &jwkSet); err != nil {
			return nil, fmt.Errorf("failed to unmarshal single key as JWK set: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid keys format in JWKS response")
	}

	// Create KeyStore and load keys
	keyStore := NewKeyStore()
	if err := keyStore.LoadFromJWKSet(&jwkSet); err != nil {
		return nil, fmt.Errorf("failed to load JWKS: %w", err)
	}

	// Cache the result
	c.mutex.Lock()
	c.entries[cacheKey] = &CacheEntry{
		KeyStore:  keyStore,
		ExpiresAt: time.Now().Add(10 * time.Minute), // 10 minutes cache
	}
	c.mutex.Unlock()

	log.Printf("JWKS cached successfully with key: %s", cacheKey)

	return keyStore, nil
}

// createSignedRequest creates an HTTP request with Mercury signature authentication
func (c *Cache) createSignedRequest(jwksUri, path string) (*http.Request, error) {
	req, err := http.NewRequest("GET", jwksUri, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Add authentication headers
	config := utils.GetConfig()
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	signatureInput := fmt.Sprintf("GET/%s%s", path, timestamp)

	// Create HMAC signature
	h := hmac.New(sha256.New, []byte(config.SignatureSharedSecret))
	h.Write([]byte(signatureInput))
	signature := fmt.Sprintf("%x", h.Sum(nil))

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-Auth-SDK/1.0")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)

	return req, nil
}

// InvalidateCache removes a cached entry
func (c *Cache) InvalidateCache(cacheKey string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	delete(c.entries, cacheKey)
}

// ClearCache removes all cached entries
func (c *Cache) ClearCache() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.entries = make(map[string]*CacheEntry)
}