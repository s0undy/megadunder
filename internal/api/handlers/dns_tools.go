package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/s0undy/megadunder/internal/api/models"
)

// DNSToolsHandler handles DNS lookup requests
type DNSToolsHandler struct{}

// NewDNSToolsHandler creates a new DNS tools handler
func NewDNSToolsHandler() *DNSToolsHandler {
	return &DNSToolsHandler{}
}

// Handle processes DNS lookup requests
func (h *DNSToolsHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.DNSLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		h.sendError(w, "Name to lookup is required")
		return
	}

	if !h.isValidRecordType(req.RecordType) {
		h.sendError(w, "Invalid record type")
		return
	}

	response := h.executeDNSLookup(req)
	h.sendResponse(w, response)
}

// isValidRecordType checks if the record type is supported
func (h *DNSToolsHandler) isValidRecordType(recordType string) bool {
	validTypes := map[string]bool{
		"A":     true,
		"AAAA":  true,
		"CNAME": true,
		"MX":    true,
		"TXT":   true,
		"NS":    true,
		"SOA":   true,
		"PTR":   true,
	}
	return validTypes[recordType]
}

// executeDNSLookup performs the DNS lookup using dig
func (h *DNSToolsHandler) executeDNSLookup(req models.DNSLookupRequest) *models.DNSLookupResponse {
	// Build the dig command with +noall +answer for clean output
	args := []string{"+noall", "+answer", "-t", req.RecordType}

	// For PTR records, ensure the IP address is properly formatted
	if req.RecordType == "PTR" {
		if !strings.HasSuffix(req.Name, ".in-addr.arpa") && !strings.HasSuffix(req.Name, ".ip6.arpa") {
			// Convert IP to reverse lookup format if needed
			args = append(args, "-x", req.Name)
		} else {
			args = append(args, req.Name)
		}
	} else {
		args = append(args, req.Name)
	}

	// Execute dig command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", args...)
	output, err := cmd.CombinedOutput()

	response := &models.DNSLookupResponse{
		Output: string(output),
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			response.Error = "DNS lookup timed out after 10 seconds"
		} else {
			response.Error = err.Error()
		}
	} else if strings.TrimSpace(response.Output) == "" {
		response.Output = "No records found"
	}

	return response
}

// sendError sends an error response
func (h *DNSToolsHandler) sendError(w http.ResponseWriter, message string) {
	h.sendResponse(w, &models.DNSLookupResponse{
		Error: message,
	})
}

// sendResponse sends a JSON response
func (h *DNSToolsHandler) sendResponse(w http.ResponseWriter, response *models.DNSLookupResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
