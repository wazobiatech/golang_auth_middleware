package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/wazobiatech/auth-middleware-go/pkg/utils"
)

// ServiceClient handles communication with Mercury service for authentication operations
type ServiceClient struct {
	httpClient *http.Client
	config     *utils.Config
}

// NewServiceClient creates a new service client instance
func NewServiceClient() *ServiceClient {
	return &ServiceClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		config: utils.GetConfig(),
	}
}

// GenerateTokenRequest represents the request payload for token generation
type GenerateTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

// GenerateTokenResponse represents the response from token generation
type GenerateTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

// GraphQLRequest represents a GraphQL request
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse represents a GraphQL response
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
		Path    []interface{} `json:"path,omitempty"`
	} `json:"errors,omitempty"`
}

// GenerateServiceTokenData represents the structure of the generateServiceToken response
type GenerateServiceTokenData struct {
	GenerateServiceToken GenerateTokenResponse `json:"generateServiceToken"`
}

// GetRegisteredServiceByClientIdData represents the structure of the getRegisteredServiceByClientId response
type GetRegisteredServiceByClientIdData struct {
	GetRegisteredServiceByClientId struct {
		UUID string `json:"uuid"`
	} `json:"getRegisteredServiceByClientId"`
}

// GetRegisteredServiceByClientIdRequest represents the input for getting service by client ID
type GetRegisteredServiceByClientIdRequest struct {
	ClientID string `json:"client_id"`
}

// GraphQL queries
const (
	generateServiceTokenMutation = `
		mutation GenerateServiceToken($input: ServiceTokenInput) {
			generateServiceToken(input: $input) {
				access_token
				scope
				token_type
				expires_in
			}
		}
	`

	getRegisteredServiceByClientIdMutation = `
		mutation GetRegisteredServiceByClientId($input: GetRegisteredServiceByClientIdInput) {
			getRegisteredServiceByClientId(input: $input) {
				uuid
			}
		}
	`
)

// Cache TTL constants (in seconds) - mirror Laravel config values
const (
	// ServiceTokenTTL is the cache duration for service tokens (~55 minutes)
	ServiceTokenTTL = 3300
	// ServiceUUIDTTL is the cache duration for service UUID lookups (24 hours)
	ServiceUUIDTTL = 86400
	// DefaultServiceTokenCacheTTL is the default cache time for service tokens from env variable
	DefaultServiceTokenCacheTTL = "SERVICE_TOKEN_CACHE_TTL"
	// DefaultServiceUUIDCacheTTL is the default cache time for service UUID from env variable
	DefaultServiceUUIDCacheTTL = "SERVICE_UUID_CACHE_TTL"
)

// GenerateToken generates a service token using client credentials
func (c *ServiceClient) GenerateToken() (string, error) {
	if c.config.ClientID == "" {
		return "", fmt.Errorf("missing required environment variable: CLIENT_ID")
	}
	if c.config.ClientSecret == "" {
		return "", fmt.Errorf("missing required environment variable: CLIENT_SECRET")
	}
	if c.config.MercuryBaseURL == "" {
		return "", fmt.Errorf("missing required environment variable: MERCURY_BASE_URL")
	}

	graphqlURL := fmt.Sprintf("%s/graphql", c.config.MercuryBaseURL)
	
	variables := map[string]interface{}{
		"input": GenerateTokenRequest{
			ClientID:     c.config.ClientID,
			ClientSecret: c.config.ClientSecret,
			Scope:        "services:read",
		},
	}

	request := GraphQLRequest{
		Query:     generateServiceTokenMutation,
		Variables: variables,
	}

	response, err := c.makeGraphQLRequest(graphqlURL, request, nil)
	if err != nil {
		return "", fmt.Errorf("failed to generate service token: %w", err)
	}

	var data GenerateServiceTokenData
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return data.GenerateServiceToken.AccessToken, nil
}

// GetServiceByID fetches the service UUID from Mercury using the provided access token
func (c *ServiceClient) GetServiceByID(accessToken string) (string, error) {
	if c.config.ClientID == "" {
		return "", fmt.Errorf("missing required environment variable: CLIENT_ID")
	}
	if c.config.MercuryBaseURL == "" {
		return "", fmt.Errorf("missing required environment variable: MERCURY_BASE_URL")
	}

	graphqlURL := fmt.Sprintf("%s/graphql", c.config.MercuryBaseURL)
	
	variables := map[string]interface{}{
		"input": GetRegisteredServiceByClientIdRequest{
			ClientID: c.config.ClientID,
		},
	}

	request := GraphQLRequest{
		Query:     getRegisteredServiceByClientIdMutation,
		Variables: variables,
	}

	headers := map[string]string{
		"x-project-token": fmt.Sprintf("Bearer %s", accessToken),
	}

	response, err := c.makeGraphQLRequest(graphqlURL, request, headers)
	if err != nil {
		return "", fmt.Errorf("failed to fetch service by ID: %w", err)
	}

	var data GetRegisteredServiceByClientIdData
	if err := json.Unmarshal(response.Data, &data); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return data.GetRegisteredServiceByClientId.UUID, nil
}

// makeGraphQLRequest performs a GraphQL request with proper error handling
func (c *ServiceClient) makeGraphQLRequest(url string, request GraphQLRequest, headers map[string]string) (*GraphQLResponse, error) {
	// Marshal request body
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-Auth-Client/1.0")

	// Add custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Check HTTP status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s - %s", resp.StatusCode, resp.Status, string(respBody))
	}

	// Parse GraphQL response
	var graphqlResp GraphQLResponse
	if err := json.Unmarshal(respBody, &graphqlResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal GraphQL response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphqlResp.Errors) > 0 {
		errMessages := make([]string, len(graphqlResp.Errors))
		for i, gqlErr := range graphqlResp.Errors {
			errMessages[i] = gqlErr.Message
		}
		return nil, fmt.Errorf("GraphQL errors: %v", errMessages)
	}

	// Check if data is present
	if len(graphqlResp.Data) == 0 {
		return nil, fmt.Errorf("no data returned from GraphQL endpoint")
	}

	return &graphqlResp, nil
}

// SetTimeout sets the HTTP client timeout
func (c *ServiceClient) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

// HealthCheck performs a health check on the Mercury service
func (c *ServiceClient) HealthCheck() error {
	if c.config.MercuryBaseURL == "" {
		return fmt.Errorf("MERCURY_BASE_URL not configured")
	}

	healthURL := fmt.Sprintf("%s/health", c.config.MercuryBaseURL)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", healthURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("User-Agent", "Go-Auth-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("health check failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// GetConfig returns the client configuration
func (c *ServiceClient) GetConfig() *utils.Config {
	return c.config
}