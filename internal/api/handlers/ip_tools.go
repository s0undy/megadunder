package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/s0undy/megadunder/internal/api/models"
)

// IPToolsHandler handles IP-related tool requests
type IPToolsHandler struct {
	ipv4Handler IPHandler
	ipv6Handler IPHandler
}

// NewIPToolsHandler creates a new IP tools handler
func NewIPToolsHandler() *IPToolsHandler {
	return &IPToolsHandler{
		ipv4Handler: NewIPv4Handler(),
		ipv6Handler: NewIPv6Handler(),
	}
}

// Handle processes IP tools requests
func (h *IPToolsHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.IPToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.IPAddress == "" {
		h.sendError(w, "IP address is required")
		return
	}

	var response *models.IPToolsResponse
	switch req.IPVersion {
	case "ipv4":
		if req.Command == "curl" {
			response = h.ipv4Handler.(interface {
				ExecuteCommandWithOptions(string, string, interface{}) *models.IPToolsResponse
			}).
				ExecuteCommandWithOptions(req.Command, req.IPAddress, req.CurlOptions)
		} else {
			response = h.ipv4Handler.ExecuteCommand(req.Command, req.IPAddress)
		}
	case "ipv6":
		if req.Command == "curl" {
			response = h.ipv6Handler.(interface {
				ExecuteCommandWithOptions(string, string, interface{}) *models.IPToolsResponse
			}).
				ExecuteCommandWithOptions(req.Command, req.IPAddress, req.CurlOptions)
		} else {
			response = h.ipv6Handler.ExecuteCommand(req.Command, req.IPAddress)
		}
	default:
		response = &models.IPToolsResponse{
			Error: "Invalid IP version. Must be 'ipv4' or 'ipv6'",
		}
	}

	h.sendResponse(w, response)
}

// sendError sends an error response
func (h *IPToolsHandler) sendError(w http.ResponseWriter, message string) {
	h.sendResponse(w, &models.IPToolsResponse{
		Error: message,
	})
}

// sendResponse sends a JSON response
func (h *IPToolsHandler) sendResponse(w http.ResponseWriter, response *models.IPToolsResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
