package config

import (
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all configuration values
type Config struct {
	Debug bool
}

// Load reads the configuration from environment variables
func Load() *Config {
	// Try to load .env from different possible locations
	locations := []string{
		".env",       // Current directory
		"../../.env", // Project root when running from cmd/megadunder
		filepath.Join("cmd", "megadunder", ".env"), // Project root when running tests
	}

	var loaded bool
	for _, loc := range locations {
		if err := godotenv.Load(loc); err == nil {
			log.Printf("Loaded environment from %s", loc)
			loaded = true
			break
		} else if !os.IsNotExist(err) {
			log.Printf("Error loading %s: %v", loc, err)
		}
	}

	if !loaded {
		log.Println("No .env file found, using default values")
	}

	// Get debug value
	debug := getEnvBool("DEBUG", false)
	log.Printf("Debug mode: %v", debug)

	return &Config{
		Debug: debug,
	}
}

// getEnvBool reads a boolean environment variable with a default value
func getEnvBool(key string, defaultVal bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		log.Printf("Found environment variable %s=%s", key, v)
		b, err := strconv.ParseBool(v)
		if err != nil {
			log.Printf("Warning: Invalid boolean value for %s: %v", key, err)
			return defaultVal
		}
		return b
	}
	log.Printf("Environment variable %s not found, using default: %v", key, defaultVal)
	return defaultVal
}
