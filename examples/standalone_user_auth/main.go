package main

import (
	"log"
	"net/http"

	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// Simple HTTP server demonstrating user JWT authentication
func main() {
	jwtAuth := auth.NewJwtAuthMiddleware()

	http.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate the request
		user, err := jwtAuth.Authenticate(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error": "Unauthorized", "message": "` + err.Error() + `"}`))
			return
		}

		// User is authenticated, return profile
		response := map[string]interface{}{
			"message": "User authenticated successfully",
			"user": map[string]interface{}{
				"uuid":        user.UUID,
				"email":       user.Email,
				"tenant_id":   user.TenantID,
				"permissions": user.Permissions,
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		// Simple JSON response
		w.Write([]byte(`{"message": "User authenticated", "user": {"uuid": "` + user.UUID + `", "email": "` + user.Email + `"}}`))
	})

	http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy"}`))
	})

	log.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}