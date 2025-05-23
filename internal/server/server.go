package server

import (
	"html/template"
	"log"
	"net/http"
	"path/filepath"

	"github.com/s0undy/megadunder/internal/api/handlers"
	"github.com/s0undy/megadunder/internal/middleware"
)

// Server represents our HTTP server
type Server struct {
	port     string
	router   *http.ServeMux
	template *template.Template
}

// New creates a new server instance
func New(port string) *Server {
	// Parse templates
	tmpl, err := template.ParseFiles(filepath.Join("internal", "templates", "index.html"))
	if err != nil {
		log.Fatalf("Failed to parse templates: %v", err)
	}

	return &Server{
		port:     port,
		router:   http.NewServeMux(),
		template: tmpl,
	}
}

// Start initializes and starts the HTTP server
func (s *Server) Start() error {
	// Set up routes
	s.setupRoutes()

	// Create server with logging middleware
	handler := middleware.LoggingMiddleware(s.router)

	// Start the server
	log.Printf("Server starting on port %s\n", s.port)
	return http.ListenAndServe(":"+s.port, handler)
}

// setupRoutes configures all the routes for the server
func (s *Server) setupRoutes() {
	s.router.HandleFunc("/", s.handleIndex)

	// API routes
	ipToolsHandler := handlers.NewIPToolsHandler()
	s.router.HandleFunc("/api/ip-tools", ipToolsHandler.Handle)
}

// handleIndex handles the index page request
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if err := s.template.Execute(w, nil); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
