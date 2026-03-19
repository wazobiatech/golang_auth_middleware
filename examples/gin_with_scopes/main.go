package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/wazobiatech/auth-middleware-go/pkg/adapters/gin as authGin"
)

// Gin example with scope-based authorization
func main() {
	r := gin.Default()

	// Public endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "healthy",
		})
	})

	// User API with JWT authentication
	user := r.Group("/api/user")
	user.Use(authGin.JWTMiddleware())
	{
		user.GET("/profile", func(c *gin.Context) {
			user, exists := c.Get(authGin.AuthUserKey)
			if !exists {
				c.JSON(500, gin.H{"error": "User not found in context"})
				return
			}
			c.JSON(200, gin.H{
				"message": "User profile retrieved successfully",
				"user":    user,
			})
		})

		user.GET("/settings", func(c *gin.Context) {
			// Only accessible with users:read scope
			user, _ := c.Get(authGin.AuthUserKey)
			c.JSON(200, gin.H{
				"message": "Settings retrieved",
				"user":    user,
			})
		})
	}

	// Project API with project token authentication
	project := r.Group("/api/project")
	project.Use(authGin.ProjectMiddleware("billing-service"))
	{
		project.GET("/data", func(c *gin.Context) {
			project, exists := c.Get(authGin.ProjectKey)
			if !exists {
				c.JSON(500, gin.H{"error": "Project not found in context"})
				return
			}
			c.JSON(200, gin.H{
				"message": "Project data retrieved",
				"project": project,
			})
		})

		// Scoped endpoint - requires specific scope
		project.GET("/invoices", authGin.RequireScope("billing:read"), func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "Invoices list",
				"invoices": []string{"INV-001", "INV-002"},
			})
		})

		// Admin endpoint - requires specific scope
		project.GET("/admin/overview", authGin.RequireScope("admin:billing:read"), func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "Admin billing overview",
				"total_revenue": 150000,
				"invoice_count": 120,
			})
		})
	}

	// Protected API with combined authentication
	secured := r.Group("/api/secure")
	secured.Use(authGin.JWTMiddleware(), authGin.ProjectMiddleware("payment-service"))
	{
		secured.GET("/data", func(c *gin.Context) {
			user, _ := c.Get(authGin.AuthUserKey)
			project, _ := c.Get(authGin.ProjectKey)
			c.JSON(200, gin.H{
				"message": "Secure data accessible only to authenticated users and projects",
				"user":    user,
				"project": project,
			})
		})
	}

	log.Println("Gin server starting on :8080")
	r.Run(":8080")
}