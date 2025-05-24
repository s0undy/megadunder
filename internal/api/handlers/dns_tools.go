package handlers

import (
	"context"
	"encoding/json"
	"fmt"
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

	// If DNSSEC validation is requested, add the validation results
	if req.CheckDNSSEC {
		dnssecInfo := h.checkDNSSEC(req.Name)
		response.DNSSECInfo = dnssecInfo
	}

	h.sendResponse(w, response)
}

// isValidRecordType checks if the record type is supported
func (h *DNSToolsHandler) isValidRecordType(recordType string) bool {
	validTypes := map[string]bool{
		"A":      true,
		"AAAA":   true,
		"CNAME":  true,
		"MX":     true,
		"TXT":    true,
		"NS":     true,
		"SOA":    true,
		"PTR":    true,
		"DNSKEY": true,
		"DS":     true,
		"RRSIG":  true,
		"NSEC":   true,
		"NSEC3":  true,
	}
	return validTypes[recordType]
}

// executeDNSLookup performs the DNS lookup using dig
func (h *DNSToolsHandler) executeDNSLookup(req models.DNSLookupRequest) *models.DNSLookupResponse {
	// Build the dig command with +noall +answer for clean output
	args := []string{"+noall", "+answer"}

	// Add DNSSEC-related flags if DNSSEC checking is requested
	if req.CheckDNSSEC {
		args = append(args, "+dnssec", "+multiline")
	}

	args = append(args, "-t", req.RecordType)

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

// checkDNSSEC performs DNSSEC validation for a domain
func (h *DNSToolsHandler) checkDNSSEC(domain string) *models.DNSSECInfo {
	info := &models.DNSSECInfo{
		Enabled: false,
		Status:  "DNSSEC not enabled",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// First, check for DS records in the parent zone
	cmd := exec.CommandContext(ctx, "dig", "+multiline", "-t", "DS", domain)
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), " DS ") {
		info.HasDS = true
		info.DSRecords = string(output)
		info.Enabled = true
		info.Status = "DNSSEC enabled"
	}

	// Check for DNSKEY records
	cmd = exec.CommandContext(ctx, "dig", "+dnssec", "+cd", "+multiline", "-t", "DNSKEY", domain)
	output, err = cmd.CombinedOutput()
	if err != nil {
		info.Error = fmt.Sprintf("Error checking DNSKEY: %v", err)
		return info
	}

	if strings.Contains(string(output), "DNSKEY") {
		info.Enabled = true
		info.Status = "DNSSEC enabled"

		// Perform DNSSEC validation with specific flags
		cmd = exec.CommandContext(ctx, "dig", "+dnssec", "+cd", "+multiline", "+trusted-key=auto", domain)
		_, _ = cmd.CombinedOutput() // Run the command but ignore output, it's just to prime the resolver

		// Try validation with AD flag
		cmd = exec.CommandContext(ctx, "dig", "+dnssec", "+multiline", domain)
		validationOutput, _ := cmd.CombinedOutput()

		validationStr := string(validationOutput)

		// Check for AD flag and RRSIG presence
		hasAD := strings.Contains(validationStr, "flags: qr rd ra ad;") ||
			strings.Contains(validationStr, "status: NOERROR")
		hasRRSIG := strings.Contains(validationStr, "RRSIG")

		if hasAD && hasRRSIG {
			info.Status = "DNSSEC enabled and validated"
			info.Validated = true
		} else if !hasAD && hasRRSIG {
			// Check if it's just that the resolver doesn't support DNSSEC
			cmd = exec.CommandContext(ctx, "dig", "+dnssec", "+cd", "+multiline", "+trusted-key=auto", "+sigchase", domain)
			sigchaseOutput, _ := cmd.CombinedOutput()

			if strings.Contains(string(sigchaseOutput), "DNSKEY") && !strings.Contains(string(sigchaseOutput), "SERVFAIL") {
				info.Status = "DNSSEC enabled and valid (resolver may not support validation)"
				info.Validated = true
			} else {
				info.Status = "DNSSEC enabled but validation failed"
				info.Validated = false
			}
		}

		// Check signature expiration
		cmd = exec.CommandContext(ctx, "dig", "+dnssec", "+multiline", "-t", "RRSIG", domain)
		output, err = cmd.CombinedOutput()
		if err == nil {
			info.SignatureInfo = h.parseSignatureInfo(string(output))
		}

		// Add more detailed validation info if available
		if info.Validated {
			var details []string
			if info.HasDS {
				details = append(details, "DS records present in parent zone")
			}
			if hasRRSIG {
				details = append(details, "RRSIG records present")
			}
			if hasAD {
				details = append(details, "AD flag set by resolver")
			}
			if len(details) > 0 {
				info.ValidationDetails = strings.Join(details, ", ")
			}
		}
	}

	return info
}

// parseSignatureInfo extracts signature expiration information from RRSIG records
func (h *DNSToolsHandler) parseSignatureInfo(output string) string {
	var result strings.Builder
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "RRSIG") {
			fields := strings.Fields(line)
			for i, field := range fields {
				if field == "RRSIG" && len(fields) > i+4 {
					result.WriteString(fmt.Sprintf("Record type: %s, Algorithm: %s, Expiration: %s\n",
						fields[i+1], fields[i+2], fields[i+4]))
				}
			}
		}
	}

	if result.Len() == 0 {
		return "No signature information found"
	}
	return result.String()
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
