package handlers

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/s0undy/megadunder/internal/api/models"
)

// IPv4Handler handles IPv4-specific operations
type IPv4Handler struct{}

// NewIPv4Handler creates a new IPv4 handler
func NewIPv4Handler() *IPv4Handler {
	return &IPv4Handler{}
}

// ValidateAddress checks if the address is valid for IPv4 operations
func (h *IPv4Handler) ValidateAddress(address string) bool {
	// For telnet, we need to handle host:port format
	if strings.Contains(address, ":") {
		host := strings.Split(address, ":")[0]
		return h.isValidHost(host)
	}

	return h.isValidHost(address)
}

// isValidHost checks if the host is a valid IPv4 address or hostname
func (h *IPv4Handler) isValidHost(host string) bool {
	// Remove protocol if present
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")

	// First, check if it's a valid IPv4 address
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.To4() != nil
	}

	// Check if it's a valid hostname
	if _, err := net.LookupHost(host); err == nil {
		return true
	}

	return false
}

// buildCurlCommand constructs the curl command with appropriate options
func (h *IPv4Handler) buildCurlCommand(address string, options models.CurlOptions) *exec.Cmd {
	args := []string{"-4", "-v", "--max-time", "10"}

	// Remove any existing protocol from the address
	address = strings.TrimPrefix(strings.TrimPrefix(address, "http://"), "https://")

	// Build the URL with the selected protocol
	url := address
	if options.Protocol != "" {
		url = fmt.Sprintf("%s://%s", options.Protocol, address)
	}

	// Handle custom port
	if options.Port != "" {
		// Split the URL into host and path
		parts := strings.SplitN(address, "/", 2)
		host := parts[0]
		path := ""
		if len(parts) > 1 {
			path = "/" + parts[1]
		}

		// Add the port to the host
		url = fmt.Sprintf("%s://%s:%s%s", options.Protocol, host, options.Port, path)
	}

	args = append(args, url)
	return exec.Command("curl", args...)
}

// ExecuteCommand runs the specified command for IPv4 addresses
func (h *IPv4Handler) ExecuteCommand(command string, address string) *models.IPToolsResponse {
	if !validateCommand(command) {
		return &models.IPToolsResponse{
			Error: "Invalid command",
		}
	}

	if !h.ValidateAddress(address) {
		return &models.IPToolsResponse{
			Error: "Invalid host or IPv4 address",
		}
	}

	var cmd *exec.Cmd
	switch command {
	case "curl":
		// Default to empty options if not provided
		cmd = h.buildCurlCommand(address, models.CurlOptions{Protocol: "http"})
	case "ping":
		cmd = exec.Command("ping", "-4", "-c", "4", address)
	case "traceroute":
		cmd = exec.Command("traceroute", "-4", address)
	case "telnet":
		parts := strings.Split(address, ":")
		if len(parts) != 2 {
			return &models.IPToolsResponse{
				Error: "Telnet requires address in format host:port",
			}
		}
		// Use timeout command as a fallback for telnet
		cmd = exec.Command("timeout", "10", "telnet", parts[0], parts[1])
	}

	return executeCommand(cmd)
}

// ExecuteCommandWithOptions runs the command with additional options
func (h *IPv4Handler) ExecuteCommandWithOptions(command string, address string, options interface{}) *models.IPToolsResponse {
	if command == "curl" {
		if curlOpts, ok := options.(models.CurlOptions); ok {
			if !h.ValidateAddress(address) {
				return &models.IPToolsResponse{
					Error: "Invalid host or IPv4 address",
				}
			}
			cmd := h.buildCurlCommand(address, curlOpts)
			return executeCommand(cmd)
		}
	}

	return h.ExecuteCommand(command, address)
}
