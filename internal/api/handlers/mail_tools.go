package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/s0undy/megadunder/internal/api/models"
)

// MailToolsHandler handles mail-related checks
type MailToolsHandler struct{}

// NewMailToolsHandler creates a new mail tools handler
func NewMailToolsHandler() *MailToolsHandler {
	return &MailToolsHandler{}
}

// Handle processes mail tool requests
func (h *MailToolsHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.MailToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request body")
		return
	}

	if req.Domain == "" {
		h.sendError(w, "Domain is required")
		return
	}

	response := &models.MailToolsResponse{}

	// Perform requested checks
	switch req.CheckType {
	case "all":
		h.performAllChecks(req, response)
	case "spf":
		h.checkSPF(req.Domain, response)
	case "dmarc":
		h.checkDMARC(req.Domain, response)
	case "dkim":
		h.checkDKIM(req.Domain, req.DKIMSelector, response)
	case "mx":
		h.checkMX(req.Domain, response)
	case "smtp":
		h.checkSMTP(req.Domain, req.SMTPOptions, response)
	default:
		h.sendError(w, "Invalid check type")
		return
	}

	h.sendResponse(w, response)
}

// performAllChecks runs all available checks
func (h *MailToolsHandler) performAllChecks(req models.MailToolsRequest, response *models.MailToolsResponse) {
	h.checkSPF(req.Domain, response)
	h.checkDMARC(req.Domain, response)
	h.checkDKIM(req.Domain, req.DKIMSelector, response)
	h.checkMX(req.Domain, response)
	h.checkSMTP(req.Domain, req.SMTPOptions, response)

	var output strings.Builder
	output.WriteString("=== Mail Configuration Check Results ===\n\n")

	if response.SPFInfo != nil {
		output.WriteString(fmt.Sprintf("SPF Check: %s\n%s\n\n", response.SPFInfo.Status, response.SPFInfo.Message))
	}
	if response.DMARCInfo != nil {
		output.WriteString(fmt.Sprintf("DMARC Check: %s\n%s\n\n", response.DMARCInfo.Status, response.DMARCInfo.Message))
	}
	if response.DKIMInfo != nil {
		output.WriteString(fmt.Sprintf("DKIM Check: %s\n%s\n\n", response.DKIMInfo.Status, response.DKIMInfo.Message))
	}
	if response.MXInfo != nil {
		output.WriteString(fmt.Sprintf("MX Check: %s\n%s\n\n", response.MXInfo.Status, response.MXInfo.Message))
	}
	if response.SMTPInfo != nil {
		output.WriteString(fmt.Sprintf("SMTP Check: %s\n%s\n", response.SMTPInfo.Status, response.SMTPInfo.Message))
	}

	response.Output = output.String()
}

// checkSPF checks SPF record configuration
func (h *MailToolsHandler) checkSPF(domain string, response *models.MailToolsResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "TXT", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		response.SPFInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "SPF Check Failed",
			Message: "Failed to lookup SPF record",
		}
		return
	}

	records := strings.Split(string(output), "\n")
	var spfRecord string
	for _, record := range records {
		if strings.Contains(record, "v=spf1") {
			spfRecord = record
			break
		}
	}

	if spfRecord == "" {
		response.SPFInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "SPF Not Found",
			Message: "No SPF record found",
			Details: []string{"SPF record is recommended for email authentication"},
		}
		return
	}

	// Analyze SPF record
	mechanisms := strings.Fields(strings.Trim(spfRecord, "\""))
	var details []string
	hasAll := false
	for _, mech := range mechanisms {
		switch {
		case strings.HasPrefix(mech, "include:"):
			details = append(details, fmt.Sprintf("Includes: %s", strings.TrimPrefix(mech, "include:")))
		case strings.HasPrefix(mech, "ip4:") || strings.HasPrefix(mech, "ip6:"):
			details = append(details, fmt.Sprintf("IP range: %s", mech))
		case strings.HasPrefix(mech, "mx"):
			details = append(details, "Uses domain's MX records")
		case strings.HasSuffix(mech, "all"):
			hasAll = true
			details = append(details, fmt.Sprintf("Default policy: %s", mech))
		}
	}

	status := "valid"
	message := "Valid SPF record found"
	if !hasAll {
		status = "warning"
		message = "SPF record missing terminal 'all' mechanism"
	}

	response.SPFInfo = &models.CheckInfo{
		Status:  status,
		Title:   "SPF Check",
		Message: message,
		Details: details,
	}
}

// checkDMARC checks DMARC record configuration
func (h *MailToolsHandler) checkDMARC(domain string, response *models.MailToolsResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "TXT", "_dmarc."+domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		response.DMARCInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "DMARC Check Failed",
			Message: "Failed to lookup DMARC record",
		}
		return
	}

	records := strings.Split(string(output), "\n")
	var dmarcRecord string
	for _, record := range records {
		if strings.Contains(record, "v=DMARC1") {
			dmarcRecord = record
			break
		}
	}

	if dmarcRecord == "" {
		response.DMARCInfo = &models.CheckInfo{
			Status:  "warning",
			Title:   "DMARC Not Found",
			Message: "No DMARC record found",
			Details: []string{"DMARC record is recommended for enhanced email security"},
		}
		return
	}

	// Analyze DMARC record
	parts := strings.Split(strings.Trim(dmarcRecord, "\""), ";")
	var details []string
	policy := "none"
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "p="):
			policy = strings.TrimPrefix(part, "p=")
			details = append(details, fmt.Sprintf("Policy: %s", policy))
		case strings.HasPrefix(part, "rua="):
			details = append(details, fmt.Sprintf("Aggregate reports: %s", strings.TrimPrefix(part, "rua=")))
		case strings.HasPrefix(part, "ruf="):
			details = append(details, fmt.Sprintf("Forensic reports: %s", strings.TrimPrefix(part, "ruf=")))
		case strings.HasPrefix(part, "pct="):
			details = append(details, fmt.Sprintf("Policy application: %s%%", strings.TrimPrefix(part, "pct=")))
		}
	}

	status := "valid"
	message := "Valid DMARC record found"
	if policy == "none" {
		status = "warning"
		message = "DMARC policy set to 'none' (monitoring only)"
	}

	response.DMARCInfo = &models.CheckInfo{
		Status:  status,
		Title:   "DMARC Check",
		Message: message,
		Details: details,
	}
}

// checkDKIM checks DKIM record configuration
func (h *MailToolsHandler) checkDKIM(domain, selector string, response *models.MailToolsResponse) {
	if selector == "" {
		selector = "default" // Try a common default selector
	}

	// Validate selector format (only allow alphanumeric characters, hyphen, and underscore)
	if !isValidSelector(selector) {
		response.DKIMInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "DKIM Check Failed",
			Message: "Invalid DKIM selector format",
			Details: []string{"Selector can only contain letters, numbers, hyphens, and underscores"},
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dkimDomain := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	cmd := exec.CommandContext(ctx, "dig", "+short", "TXT", dkimDomain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		response.DKIMInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "DKIM Check Failed",
			Message: "Failed to lookup DKIM record",
		}
		return
	}

	records := strings.Split(string(output), "\n")
	var dkimRecord string
	for _, record := range records {
		if strings.Contains(record, "v=DKIM1") {
			dkimRecord = record
			break
		}
	}

	if dkimRecord == "" {
		response.DKIMInfo = &models.CheckInfo{
			Status:  "warning",
			Title:   "DKIM Not Found",
			Message: fmt.Sprintf("No DKIM record found for selector '%s'", selector),
			Details: []string{
				"DKIM record is recommended for email authentication",
				"Try different selectors if you're sure DKIM is configured",
			},
		}
		return
	}

	// Analyze DKIM record
	parts := strings.Split(strings.Trim(dkimRecord, "\""), ";")
	var details []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch {
		case strings.HasPrefix(part, "k="):
			details = append(details, fmt.Sprintf("Key type: %s", strings.TrimPrefix(part, "k=")))
		case strings.HasPrefix(part, "p="):
			if strings.TrimPrefix(part, "p=") == "" {
				details = append(details, "Public key: REVOKED")
			} else {
				details = append(details, "Public key: Present")
			}
		case strings.HasPrefix(part, "t="):
			details = append(details, fmt.Sprintf("Flags: %s", strings.TrimPrefix(part, "t=")))
		case strings.HasPrefix(part, "s="):
			details = append(details, fmt.Sprintf("Service type: %s", strings.TrimPrefix(part, "s=")))
		}
	}

	response.DKIMInfo = &models.CheckInfo{
		Status:  "valid",
		Title:   "DKIM Check",
		Message: fmt.Sprintf("Valid DKIM record found for selector '%s'", selector),
		Details: details,
	}
}

// isValidSelector checks if a DKIM selector contains only valid characters
func isValidSelector(selector string) bool {
	for _, r := range selector {
		if !isValidSelectorChar(r) {
			return false
		}
	}
	return true
}

// isValidSelectorChar checks if a character is valid in a DKIM selector
func isValidSelectorChar(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' ||
		r == '_'
}

// checkMX checks MX record configuration
func (h *MailToolsHandler) checkMX(domain string, response *models.MailToolsResponse) {
	mxRecords, err := net.LookupMX(domain)
	if err != nil {
		response.MXInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "MX Check Failed",
			Message: "Failed to lookup MX records",
		}
		return
	}

	if len(mxRecords) == 0 {
		response.MXInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "MX Not Found",
			Message: "No MX records found",
			Details: []string{"MX records are required for receiving email"},
		}
		return
	}

	var details []string
	for _, mx := range mxRecords {
		details = append(details, fmt.Sprintf("Priority %d: %s", mx.Pref, mx.Host))
	}

	response.MXInfo = &models.CheckInfo{
		Status:  "valid",
		Title:   "MX Check",
		Message: fmt.Sprintf("Found %d MX record(s)", len(mxRecords)),
		Details: details,
	}
}

// checkSMTP tests SMTP server connectivity
func (h *MailToolsHandler) checkSMTP(domain string, options models.SMTPOptions, response *models.MailToolsResponse) {
	if options.Port == "" {
		options.Port = "25" // Default SMTP port
	}

	// First, get MX records to find the mail server
	mxRecords, err := net.LookupMX(domain)
	if err != nil || len(mxRecords) == 0 {
		response.SMTPInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "SMTP Check Failed",
			Message: "No MX records found to test SMTP",
		}
		return
	}

	// Try to connect to the first MX record
	server := strings.TrimSuffix(mxRecords[0].Host, ".")

	// Format address to handle both IPv4 and IPv6
	address := server + ":" + options.Port
	if strings.Contains(server, ":") {
		// IPv6 address needs to be enclosed in square brackets
		address = fmt.Sprintf("[%s]:%s", server, options.Port)
	}

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		response.SMTPInfo = &models.CheckInfo{
			Status:  "error",
			Title:   "SMTP Connection Failed",
			Message: fmt.Sprintf("Could not connect to %s", address),
			Details: []string{err.Error()},
		}
		return
	}
	defer conn.Close()

	// If TLS check is requested
	details := []string{fmt.Sprintf("Successfully connected to %s", server)}
	if options.CheckTLS {
		// Test STARTTLS using openssl
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "openssl", "s_client", "-starttls", "smtp", "-connect", address)
		output, err := cmd.CombinedOutput()
		if err != nil {
			details = append(details, "STARTTLS not supported or failed")
		} else {
			outputStr := string(output)
			if strings.Contains(outputStr, "BEGIN CERTIFICATE") {
				details = append(details, "STARTTLS supported")
				if strings.Contains(outputStr, "Verify return code: 0") {
					details = append(details, "Valid TLS certificate")
				} else {
					details = append(details, "TLS certificate validation failed")
				}
			}
		}
	}

	response.SMTPInfo = &models.CheckInfo{
		Status:  "valid",
		Title:   "SMTP Check",
		Message: fmt.Sprintf("SMTP server responding on port %s", options.Port),
		Details: details,
	}
}

// sendError sends an error response
func (h *MailToolsHandler) sendError(w http.ResponseWriter, message string) {
	h.sendResponse(w, &models.MailToolsResponse{
		Error: message,
	})
}

// sendResponse sends a JSON response
func (h *MailToolsHandler) sendResponse(w http.ResponseWriter, response *models.MailToolsResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
