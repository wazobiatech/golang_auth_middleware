package main

import (
	"log"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/wazobiatech/auth-middleware-go/pkg/auth"
	"github.com/wazobiatech/auth-middleware-go/pkg/types"
)

// GraphQL context example

// GraphQLContext wraps authentication contexts for GraphQL resolvers
type GraphQLContext struct {
	Request *http.Request
	User    *types.AuthUser
	Project *types.ProjectContext
	Service *types.ServiceContext
	Platform *types.PlatformContext
}

// This is a simple example - in production you'd use a real GraphQL schema

func main() {
	// JWT auth helper
	jwtAuth := auth.NewJwtAuthMiddleware()
	projectAuth := auth.NewProjectAuthMiddleware("graphql-service")

	// GraphQL handler with authentication
	http.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		// Create auth context
		ctx := &GraphQLContext{
			Request: r,
		}

		// Try to authenticate with user token
		user, err := jwtAuth.Authenticate(r)
		if err == nil {
			ctx.User = user
		}

		// Try to authenticate with project token (could be combined)
		authReq, err := projectAuth.Authenticate(r)
		if err == nil {
			ctx.Project = authReq.Project
			ctx.Service = authReq.Service
			ctx.Platform = authReq.Platform
		}

		// Create GraphQL server with context
		// In production, you'd pass ctx to your resolver functions
		
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data": {"message": "GraphQL endpoint reached", "authenticated": ` + 
			boolToString(ctx.User != nil || ctx.Project != nil) + `}}`))
	})

	// GraphQL playground
	http.HandleFunc("/playground", playground.Handler("GraphQL Playground", "/graphql"))

	log.Println("GraphQL server with auth at http://localhost:8080/graphql")
	log.Println("GraphQL playground at http://localhost:8080/playground")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}