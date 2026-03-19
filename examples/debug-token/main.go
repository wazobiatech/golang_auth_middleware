package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Debug token utility - decodes and verifies JWT token structure
// Similar to node_auth_middleware/debug-token.js

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <jwt-token>")
		fmt.Println("Or pipe token to stdin")
		os.Exit(1)
	}

	token := os.Args[1]
	if token == "" {
		fmt.Println("No token provided")
		os.Exit(1)
	}

	fmt.Println("🔍 Decoding JWT Token...")
	fmt.Println()

	// Decode the token
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		fmt.Printf("❌ Invalid JWT format: expected 3 parts, got %d\n", len(parts))
		os.Exit(1)
	}

	// Decode header
	headerData, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		fmt.Printf("❌ Error decoding header: %v\n", err)
		os.Exit(1)
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerData, &header); err != nil {
		fmt.Printf("❌ Error parsing header: %v\n", err)
		os.Exit(1)
	}

	// Decode payload
	payloadData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Printf("❌ Error decoding payload: %v\n", err)
		os.Exit(1)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadData, &payload); err != nil {
		fmt.Printf("❌ Error parsing payload: %v\n", err)
		os.Exit(1)
	}

	// Output decoded info
	fmt.Println("📋 JWT Header:")
	headerJSON, _ := json.MarshalIndent(header, "", "  ")
	fmt.Println(string(headerJSON))
	fmt.Println()

	fmt.Println("📊 JWT Payload:")
	payloadJSON, _ := json.MarshalIndent(payload, "", "  ")
	fmt.Println(string(payloadJSON))
	fmt.Println()

	// Extract key fields
	fmt.Println("🎯 Key Fields:")

	// sub field (contains user info)
	if sub, exists := payload["sub"]; exists {
		if subMap, ok := sub.(map[string]interface{}); ok {
			if uuid, ok := subMap["uuid"].(string); ok {
				fmt.Printf("- User UUID: %s\n", uuid)
			}
			if email, ok := subMap["email"].(string); ok {
				fmt.Printf("- User Email: %s\n", email)
			}
			if name, ok := subMap["name"].(string); ok {
				fmt.Printf("- User Name: %s\n", name)
			}
		}
	}

	// Other fields
	if tokenType, ok := payload["type"].(string); ok {
		fmt.Printf("- Token Type: %s\n", tokenType)
	}

	if tenantID, ok := payload["tenant_id"].(string); ok {
		fmt.Printf("- Tenant ID: %s\n", tenantID)
	}

	if projectUUID, ok := payload["project_uuid"].(string); ok {
		fmt.Printf("- Project UUID: %s\n", projectUUID)
	}

	if jti, ok := payload["jti"].(string); ok {
		fmt.Printf("- Token ID: %s\n", jti)
	}

	if iss, ok := payload["iss"].(string); ok {
		fmt.Printf("- Issuer: %s\n", iss)
	}

	if aud, ok := payload["aud"].(string); ok {
		fmt.Printf("- Audience: %s\n", aud)
	}

	if permissions, ok := payload["permissions"]; ok {
		if perms, ok := permissions.([]interface{}); ok {
			fmt.Printf("- Permissions Count: %d\n", len(perms))
			fmt.Printf("- Permissions: %v\n", perms)
		}
	}

	if scopes, ok := payload["scopes"]; ok {
		if scps, ok := scopes.([]interface{}); ok {
			fmt.Printf("- Scopes: %v\n", scps)
		}
	}

	if iat, ok := payload["iat"].(float64); ok {
		fmt.Printf("- Issued At: %d\n", int64(iat))
	}

	if exp, ok := payload["exp"].(float64); ok {
		fmt.Printf("- Expires At: %d\n", int64(exp))
	}

	// Expected AuthUser structure
	fmt.Println()
	fmt.Println("✅ Expected AuthUser Structure:")

	var userUUID, userEmail, userName, tenantID, tokenID string
	var permissions []string

	// Extract from sub field
	if sub, exists := payload["sub"]; exists {
		if subMap, ok := sub.(map[string]interface{}); ok {
			if uuid, ok := subMap["uuid"].(string); ok {
				userUUID = uuid
			}
			if email, ok := subMap["email"].(string); ok {
				userEmail = email
			}
			if name, ok := subMap["name"].(string); ok {
				userName = name
			}
		}
	}

	if tID, ok := payload["tenant_id"].(string); ok {
		tenantID = tID
	}

	if projID, ok := payload["project_uuid"].(string); ok {
		tenantID = projID
	}

	if jti, ok := payload["jti"].(string); ok {
		tokenID = jti
	}

	if perms, ok := payload["permissions"].([]interface{}); ok {
		permissions = make([]string, len(perms))
		for i, p := range perms {
			if s, ok := p.(string); ok {
				permissions[i] = s
			}
		}
	}

	authUser := map[string]interface{}{
		"uuid":        userUUID,
		"email":       userEmail,
		"name":        userName,
		"tenant_id":   tenantID,
		"permissions": permissions,
		"token_id":    tokenID,
	}

	userJSON, _ := json.MarshalIndent(authUser, "", "  ")
	fmt.Println(string(userJSON))

	// Warning about permissions
	if len(permissions) == 0 {
		fmt.Println()
		fmt.Println("⚠️  WARNING: No permissions found in token!")
		fmt.Println("⚠️  Check if permissions are being lost in authentication flow!")
	}
}