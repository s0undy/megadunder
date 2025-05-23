package main

import (
	"embed"
	"log"
	"os"
	"path/filepath"

	"github.com/s0undy/megadunder/internal/config"
	"github.com/s0undy/megadunder/internal/server"
)

//go:embed templates/*
var templateFS embed.FS

func main() {
	// Change to project root directory if needed
	if filepath.Base(os.Getenv("PWD")) == "megadunder" {
		log.Println("Already in project root directory")
	} else {
		// Try to find and change to project root
		for i := 0; i < 3; i++ { // Try up to 3 levels up
			if _, err := os.Stat(".env"); err == nil {
				log.Println("Found project root directory")
				break
			}
			if err := os.Chdir(".."); err != nil {
				log.Printf("Warning: Could not change directory: %v", err)
				break
			}
		}
	}

	// Log current directory
	if pwd, err := os.Getwd(); err == nil {
		log.Printf("Current directory: %s", pwd)
	}

	// Load configuration
	cfg := config.Load()

	// Create and start server
	srv := server.New("8080", templateFS, cfg)
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
}
