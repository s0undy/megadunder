package middleware

import (
	"log"
	"net/http"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware logs information about each HTTP request
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a custom response writer to capture the status code
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK, // Default to 200 OK
		}

		// Process the request
		next.ServeHTTP(rw, r)

		// Calculate duration
		duration := time.Since(start)

		// Log the request details
		log.Printf(
			"[%s] %s %s - Status: %d - Duration: %v",
			r.RemoteAddr,
			r.Method,
			r.URL.Path,
			rw.statusCode,
			duration,
		)
	})
}
