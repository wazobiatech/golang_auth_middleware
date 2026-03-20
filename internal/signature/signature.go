package signature

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/wazobiatech/auth-middleware-go/internal/config"
)

// Signer handles HMAC signature creation for Mercury API requests
type Signer struct {
	sharedSecret string
}

// NewSigner creates a new signer instance
func NewSigner() *Signer {
	cfg := config.GetConfig()
	return &Signer{
		sharedSecret: cfg.SignatureSharedSecret,
	}
}

// CreateSignature creates an HMAC-SHA256 signature for the given method, path, and timestamp
func (s *Signer) CreateSignature(method, path, timestamp string) string {
	signatureInput := method + path + timestamp
	h := hmac.New(sha256.New, []byte(s.sharedSecret))
	h.Write([]byte(signatureInput))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// CreateSignatureWithTimestamp creates a signature with current timestamp
func (s *Signer) CreateSignatureWithTimestamp(method, path string) (string, string) {
	timestamp := fmt.Sprintf("%d", time.Now().UnixMilli())
	signature := s.CreateSignature(method, path, timestamp)
	return signature, timestamp
}

// GetAuthHeaders returns the authentication headers for Mercury API requests
func (s *Signer) GetAuthHeaders(method, path string) map[string]string {
	signature, timestamp := s.CreateSignatureWithTimestamp(method, path)
	return map[string]string{
		"Accept":      "application/json",
		"User-Agent":  "Go-Auth-SDK/2.0",
		"X-Timestamp": timestamp,
		"X-Signature": signature,
	}
}
