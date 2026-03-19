package main

import (
	"fmt"
	"log"
	"time"

	"github.com/wazobiatech/auth-middleware-go/pkg/client"
)

// Service-to-service authentication example
func main() {
	// Create service client for authenticating with Mercury
	serviceClient := client.NewServiceClient()

	// Example 1: Generate a service token
	fmt.Println("=== Generating Service Token ===")
	accessToken, err := serviceClient.GenerateToken()
	if err != nil {
		log.Fatalf("Failed to generate service token: %v", err)
	}
	fmt.Printf("Service token generated successfully\n")
	fmt.Printf("Token prefix: %s...\n", accessToken[:min(30, len(accessToken))])

	// Example 2: Get service UUID by client ID
	fmt.Println("\n=== Getting Service UUID ===")
	serviceUUID, err := serviceClient.GetServiceByID(accessToken)
	if err != nil {
		log.Fatalf("Failed to get service UUID: %v", err)
	}
	fmt.Printf("Service UUID: %s\n", serviceUUID)

	// Example 3: Use the token for protected API calls
	fmt.Println("\n=== Service-to-Service API Call ===")
	// In a real service, you'd use this token like:
	// - Set header: x-project-token: Bearer <accessToken>
	// - Or: Authorization: Bearer <accessToken>
	// - Call your protected endpoints

	fmt.Println("Token generated successfully! Use it in API calls:")
	fmt.Printf("Header: x-project-token: Bearer %s\n", accessToken)
	fmt.Println("\nExample cURL command:")
	fmt.Printf("curl -H \"x-project-token: Bearer %s...\" http://your-service/api/resource\n", accessToken[:50])

	// Example 4: Token cache demonstration
	fmt.Println("\n=== Token Cache Demo ===")
	fmt.Println("Generating token again (should use cache):")
	start := time.Now()
	cachedToken, err := serviceClient.GenerateToken()
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}
	elapsed := time.Since(start)
	fmt.Printf("Token retrieved from cache in %v\n", elapsed)
	fmt.Printf("Is cached token same?: %v\n", cachedToken == accessToken)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}