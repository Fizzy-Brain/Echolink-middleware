package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, relying on environment variables")
	}

	// Verify required environment variables
	requiredEnvVars := []string{
		"HEADSCALE_URL",
		"HEADSCALE_API_KEY",
		"GOOGLE_CLIENT_ID",
	}

	for _, env := range requiredEnvVars {
		if os.Getenv(env) == "" {
			log.Fatalf("Fatal: Environment variable %s is not set", env)
		}
	}

	// Initialize the in-memory store for guest PINs
	InitStore()

	// Initialize Gin router
	router := gin.Default()

	// Setup routes
	auth := router.Group("/auth")
	{
		auth.POST("/login", HandleLogin)
		
		guest := auth.Group("/guest")
		{
			guest.POST("/invite", HandleGuestInvite)
			guest.POST("/claim", HandleGuestClaim)
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Starting EchoLink Middleware on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
