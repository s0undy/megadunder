package main

import (
	"log"

	"github.com/s0undy/systools/internal/server"
)

func main() {
	srv := server.New("8080")
	if err := srv.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
