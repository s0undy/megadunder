package server

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/s0undy/megadunder/internal/api/handlers"
	"github.com/s0undy/megadunder/internal/config"
	"github.com/s0undy/megadunder/internal/middleware"
)

// Server represents our HTTP server
type Server struct {
	port     string
	router   *http.ServeMux
	template *template.Template
	config   *config.Config
}

// New creates a new server instance with embedded templates
func New(port string, templateFS embed.FS, cfg *config.Config) *Server {
	// Parse templates in specific order to ensure dependencies are met
	tmpl := template.New("")

	// First parse the layout template
	_, err := tmpl.ParseFS(templateFS, "templates/layout.html")
	if err != nil {
		log.Fatalf("Failed to parse layout template: %v", err)
	}

	// Then parse the content templates
	_, err = tmpl.ParseFS(templateFS,
		"templates/index.html",
		"templates/ip_tools.html",
		"templates/dns_tools.html",
		"templates/cert_tools.html",
		"templates/mail_tools.html",
	)
	if err != nil {
		log.Fatalf("Failed to parse content templates: %v", err)
	}

	return &Server{
		port:     port,
		router:   http.NewServeMux(),
		template: tmpl,
		config:   cfg,
	}
}

// Start initializes and starts the HTTP server
func (s *Server) Start() error {
	// Set up routes
	s.setupRoutes()

	// Create middleware chain
	rateLimiter := middleware.NewRateLimiter(100, time.Minute) // 100 requests per minute
	handler := middleware.TimeoutMiddleware(30 * time.Second)(
		rateLimiter.RateLimit(
			middleware.SecurityHeaders(
				middleware.LoggingMiddleware(s.router),
			),
		),
	)

	// Create server with timeouts
	srv := &http.Server{
		Addr:              ":" + s.port,
		Handler:           handler,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
	}

	// Start server
	log.Printf("Server starting on port %s (Debug: %v)\n", s.port, s.config.Debug)
	return srv.ListenAndServe()
}

// setupRoutes configures all the routes for the server
func (s *Server) setupRoutes() {
	// Page routes
	s.router.HandleFunc("/", s.handleIndex)
	s.router.HandleFunc("/ip-tools", s.handleIPTools)
	s.router.HandleFunc("/dns-tools", s.handleDNSTools)
	s.router.HandleFunc("/cert-tools", s.handleCertTools)
	s.router.HandleFunc("/mail-tools", s.handleMailTools)

	// API routes
	ipToolsHandler := handlers.NewIPToolsHandler()
	dnsToolsHandler := handlers.NewDNSToolsHandler()
	certToolsHandler := &handlers.Handler{} // Initialize directly since we don't need any special setup
	mailToolsHandler := handlers.NewMailToolsHandler()
	s.router.HandleFunc("/api/ip-tools", ipToolsHandler.Handle)
	s.router.HandleFunc("/api/dns-tools", dnsToolsHandler.Handle)
	s.router.HandleFunc("/api/cert-tools", certToolsHandler.HandleCertTools)
	s.router.HandleFunc("/api/mail-tools", mailToolsHandler.Handle)
}

// handleIndex handles the index page request
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := struct {
		Title  string
		Active string
		Year   int
		Debug  bool
	}{
		Title:  "Home",
		Active: "home",
		Year:   2024,
		Debug:  s.config.Debug,
	}

	if err := s.template.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleIPTools handles the IP Tools page request
func (s *Server) handleIPTools(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title  string
		Active string
		Year   int
		Debug  bool
	}{
		Title:  "IP Tools",
		Active: "ip",
		Year:   2024,
		Debug:  s.config.Debug,
	}

	if err := s.template.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleDNSTools handles the DNS Tools page request
func (s *Server) handleDNSTools(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title  string
		Active string
		Year   int
		Debug  bool
	}{
		Title:  "DNS Tools",
		Active: "dns",
		Year:   2024,
		Debug:  s.config.Debug,
	}

	if err := s.template.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleCertTools handles the Certificate Tools page request
func (s *Server) handleCertTools(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title  string
		Active string
		Year   int
		Debug  bool
	}{
		Title:  "Certificate Tools",
		Active: "cert",
		Year:   time.Now().Year(),
		Debug:  s.config.Debug,
	}

	if err := s.template.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// handleMailTools handles the Mail Tools page request
func (s *Server) handleMailTools(w http.ResponseWriter, r *http.Request) {
	data := struct {
		Title  string
		Active string
		Year   int
		Debug  bool
	}{
		Title:  "Mail Tools",
		Active: "mail",
		Year:   time.Now().Year(),
		Debug:  s.config.Debug,
	}

	if err := s.template.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
