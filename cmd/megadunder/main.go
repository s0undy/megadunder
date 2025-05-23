package main

import (
	"embed"
	"html/template"
	"log"
	"net/http"

	"github.com/anton/megadunder/internal/handlers"
)

//go:embed templates/*
var templateFS embed.FS

func main() {
	// Parse templates
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	// Create handlers
	h := handlers.NewHandler(tmpl)

	// Routes
	http.HandleFunc("/", h.IndexHandler)
	http.HandleFunc("/ip-tools", h.IPToolsHandler)
	http.HandleFunc("/dns-tools", h.DNSToolsHandler)
	http.HandleFunc("/api/ip-tools", h.IPToolsAPIHandler)
	http.HandleFunc("/api/dns-tools", h.DNSToolsAPIHandler)

	// Start server
	log.Println("Server starting on http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
