package handlers

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/s0undy/systools/internal/api/models"
)

// IPv6Handler handles IPv6-specific operations
type IPv6Handler struct{}

// NewIPv6Handler creates a new IPv6 handler
func NewIPv6Handler() *IPv6Handler {
	return &IPv6Handler{}
}

// ValidateAddress checks if the address is valid for IPv6 operations
func (h *IPv6Handler) ValidateAddress(address string) bool {
	// For telnet, we need to handle [host]:port format
	if strings.Contains(address, "]:") {
		host := strings.Split(strings.Trim(address, "[]"), "]:")[0]
		return h.isValidHost(host)
	}

	return h.isValidHost(address)
}

// isValidHost checks if the host is a valid IPv6 address or hostname
func (h *IPv6Handler) isValidHost(host string) bool {
	// Remove protocol if present
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")

	// First, check if it's a valid IPv6 address
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.To4() == nil
	}

	// Check if it's a valid hostname with IPv6 support
	addrs, err := net.LookupIP(host)
	if err != nil {
		return false
	}

	// Check if the host has any IPv6 addresses
	for _, addr := range addrs {
		if addr.To4() == nil {
			return true
		}
	}

	return false
}

// buildCurlCommand constructs the curl command with appropriate options
func (h *IPv6Handler) buildCurlCommand(address string, options models.CurlOptions) *exec.Cmd {
	args := []string{"-6", "-v", "--max-time", "10"} // Add 10-second timeout flag

	// Remove any existing protocol from the address
	address = strings.TrimPrefix(strings.TrimPrefix(address, "http://"), "https://")

	// Build the URL with the selected protocol and proper IPv6 formatting
	url := address
	if options.Protocol != "" {
		// Handle IPv6 address formatting
		if ip := net.ParseIP(address); ip != nil && ip.To4() == nil {
			// Split the URL into host and path
			parts := strings.SplitN(address, "/", 2)
			host := parts[0]
			path := ""
			if len(parts) > 1 {
				path = "/" + parts[1]
			}

			// Add brackets for IPv6 address
			url = fmt.Sprintf("%s://[%s]%s", options.Protocol, host, path)
		} else {
			url = fmt.Sprintf("%s://%s", options.Protocol, address)
		}
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

		// Add the port to the host, ensuring proper IPv6 formatting
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			url = fmt.Sprintf("%s://[%s]:%s%s", options.Protocol, host, options.Port, path)
		} else {
			url = fmt.Sprintf("%s://%s:%s%s", options.Protocol, host, options.Port, path)
		}
	}

	args = append(args, url)
	return exec.Command("curl", args...)
}

// ExecuteCommand runs the specified command for IPv6 addresses
func (h *IPv6Handler) ExecuteCommand(command string, address string) *models.IPToolsResponse {
	if !validateCommand(command) {
		return &models.IPToolsResponse{
			Error: "Invalid command",
		}
	}

	if !h.ValidateAddress(address) {
		return &models.IPToolsResponse{
			Error: "Invalid host or IPv6 address",
		}
	}

	var cmd *exec.Cmd
	switch command {
	case "curl":
		// Default to empty options if not provided
		cmd = h.buildCurlCommand(address, models.CurlOptions{Protocol: "http"})
	case "ping":
		cmd = exec.Command("ping6", "-c", "4", address)
	case "traceroute":
		cmd = exec.Command("traceroute6", address)
	case "telnet":
		if !strings.Contains(address, "]:") {
			return &models.IPToolsResponse{
				Error: "IPv6 telnet requires address in format [host]:port",
			}
		}
		host := strings.Split(strings.Trim(address, "[]"), "]:")[0]
		port := strings.Split(address, "]:")[1]
		// Use timeout command as a fallback for telnet
		cmd = exec.Command("timeout", "10", "telnet", host, port)
	}

	return executeCommand(cmd)
}

// ExecuteCommandWithOptions runs the command with additional options
func (h *IPv6Handler) ExecuteCommandWithOptions(command string, address string, options interface{}) *models.IPToolsResponse {
	if command == "curl" {
		if curlOpts, ok := options.(models.CurlOptions); ok {
			if !h.ValidateAddress(address) {
				return &models.IPToolsResponse{
					Error: "Invalid host or IPv6 address",
				}
			}
			cmd := h.buildCurlCommand(address, curlOpts)
			return executeCommand(cmd)
		}
	}

	return h.ExecuteCommand(command, address)
}
