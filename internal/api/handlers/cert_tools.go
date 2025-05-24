package handlers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	// Add any handler dependencies here if needed
}

type CertRequest struct {
	Hostname  string `json:"hostname"`
	Port      int    `json:"port"`
	CheckType string `json:"checkType"`
}

type CertResponse struct {
	Output      string     `json:"output,omitempty"`
	Error       string     `json:"error,omitempty"`
	Chain       []CertInfo `json:"chain,omitempty"`
	ChainStatus struct {
		IsValid       bool   `json:"isValid"`
		ErrorMessage  string `json:"errorMessage,omitempty"`
		ExpiresIn     int    `json:"expiresIn"`     // Days until first expiration
		NextExpiry    string `json:"nextExpiry"`    // Which cert expires next
		ExpiryWarning string `json:"expiryWarning"` // Warning message if expiry is close
	} `json:"chainStatus,omitempty"`
}

type CertInfo struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	ValidFrom     time.Time `json:"validFrom"`
	ValidTo       time.Time `json:"validTo"`
	SerialNumber  string    `json:"serialNumber"`
	Version       int       `json:"version"`
	KeyUsage      []string  `json:"keyUsage"`
	SANs          []string  `json:"sans"`
	SignatureAlg  string    `json:"signatureAlg"`
	PublicKeyType string    `json:"publicKeyType"`
	PublicKeyBits int       `json:"publicKeyBits"`
	CRLStatus     string    `json:"crlStatus"`
	CRLDetails    string    `json:"crlDetails"`
}

func (h *Handler) HandleCertTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	var req CertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(CertResponse{
			Error: fmt.Sprintf("Invalid request format: %v", err),
		})
		return
	}

	// Validate input
	if req.Hostname == "" {
		json.NewEncoder(w).Encode(CertResponse{
			Error: "Hostname is required",
		})
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		json.NewEncoder(w).Encode(CertResponse{
			Error: "Port must be between 1 and 65535",
		})
		return
	}

	conf := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		ServerName:         req.Hostname, // Add ServerName for proper certificate validation
	}

	// Connect with timeout
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", req.Hostname, req.Port), conf)
	if err != nil {
		json.NewEncoder(w).Encode(CertResponse{
			Error: fmt.Sprintf("Connection failed: %v", err),
		})
		return
	}
	defer conn.Close()

	// Get the certificate chain
	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		json.NewEncoder(w).Encode(CertResponse{
			Error: "No certificates found in the chain",
		})
		return
	}

	switch req.CheckType {
	case "chain":
		chain := make([]CertInfo, len(certs))
		for i, cert := range certs {
			certInfo := getCertInfo(cert)
			crlStatus, crlDetails := checkCertificateRevocation(cert)
			certInfo.CRLStatus = crlStatus
			certInfo.CRLDetails = crlDetails
			chain[i] = certInfo
		}

		// Validate the certificate chain
		chainStatus := validateChain(certs)

		response := CertResponse{
			Chain:       chain,
			ChainStatus: chainStatus,
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

	case "connection":
		details := fmt.Sprintf(`
TLS Connection Details:
Protocol Version: %s
Cipher Suite: %s
Server Name: %s
ALPN Protocol: %s
Certificate Transparency: %v
`,
			getTLSVersion(state.Version),
			tls.CipherSuiteName(state.CipherSuite),
			state.ServerName,
			state.NegotiatedProtocol,
			state.VerifiedChains != nil,
		)
		if err := json.NewEncoder(w).Encode(CertResponse{Output: details}); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

	case "validation":
		result := validateCertificates(certs)
		if err := json.NewEncoder(w).Encode(CertResponse{Output: result}); err != nil {
			log.Printf("Error encoding response: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}

	default:
		json.NewEncoder(w).Encode(CertResponse{
			Error: fmt.Sprintf("Invalid check type: %s", req.CheckType),
		})
	}
}

func getCertInfo(cert *x509.Certificate) CertInfo {
	// Initialize empty arrays for slices to avoid null in JSON
	usage := make([]string, 0)
	sans := make([]string, 0)

	// Extract key usage flags
	if cert.KeyUsage != 0 {
		if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
			usage = append(usage, "Digital Signature")
		}
		if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
			usage = append(usage, "Key Encipherment")
		}
		if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
			usage = append(usage, "Certificate Sign")
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
			usage = append(usage, "CRL Sign")
		}
	}

	// Add extended key usage if present
	for _, extUsage := range cert.ExtKeyUsage {
		switch extUsage {
		case x509.ExtKeyUsageServerAuth:
			usage = append(usage, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usage = append(usage, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usage = append(usage, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usage = append(usage, "Email Protection")
		case x509.ExtKeyUsageTimeStamping:
			usage = append(usage, "Time Stamping")
		}
	}

	// Copy DNS names to avoid null
	if len(cert.DNSNames) > 0 {
		sans = append(sans, cert.DNSNames...)
	}

	return CertInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		ValidFrom:     cert.NotBefore,
		ValidTo:       cert.NotAfter,
		SerialNumber:  cert.SerialNumber.String(),
		Version:       cert.Version,
		KeyUsage:      usage,
		SANs:          sans,
		SignatureAlg:  cert.SignatureAlgorithm.String(),
		PublicKeyType: getPublicKeyType(cert),
		PublicKeyBits: getPublicKeyBits(cert),
	}
}

func getPublicKeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("Unknown (%T)", pub)
	}
}

func getPublicKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Params().BitSize
	case ed25519.PublicKey:
		return 256 // Ed25519 is always 256 bits
	default:
		return 0
	}
}

func getTLSVersion(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04X)", version)
	}
}

func validateCertificates(certs []*x509.Certificate) string {
	var result strings.Builder
	result.WriteString("Certificate Validation Results:\n\n")

	for i, cert := range certs {
		result.WriteString(fmt.Sprintf("Certificate %d:\n", i+1))

		// Check expiration
		now := time.Now()
		if now.Before(cert.NotBefore) {
			result.WriteString("❌ Certificate not yet valid\n")
		} else if now.After(cert.NotAfter) {
			result.WriteString("❌ Certificate has expired\n")
		} else {
			result.WriteString("✅ Certificate is within validity period\n")
			daysLeft := cert.NotAfter.Sub(now).Hours() / 24
			if daysLeft < 30 {
				result.WriteString(fmt.Sprintf("⚠️ Warning: Certificate expires in %.0f days\n", daysLeft))
			}
		}

		// Check key strength
		keyBits := getPublicKeyBits(cert)
		if keyBits < 2048 {
			result.WriteString("❌ Weak key strength (< 2048 bits)\n")
		} else {
			result.WriteString("✅ Adequate key strength\n")
		}

		// Check signature algorithm
		if strings.Contains(cert.SignatureAlgorithm.String(), "SHA1") {
			result.WriteString("❌ Weak signature algorithm (SHA1)\n")
		} else {
			result.WriteString("✅ Strong signature algorithm\n")
		}

		result.WriteString("\n")
	}

	return result.String()
}

// checkCertificateRevocation checks if a certificate is revoked using its CRL distribution points
func checkCertificateRevocation(cert *x509.Certificate) (status, details string) {
	if len(cert.CRLDistributionPoints) == 0 {
		return "Unknown", "No CRL distribution points found"
	}

	var results []string
	for _, crlURL := range cert.CRLDistributionPoints {
		_, detail := checkSingleCRL(cert, crlURL)
		results = append(results, fmt.Sprintf("CRL %s: %s", crlURL, detail))
	}

	// If we have results, combine them
	if len(results) > 0 {
		return "Checked", strings.Join(results, "\n")
	}

	return "Unknown", "Failed to check CRL status"
}

// checkSingleCRL checks a single CRL distribution point
func checkSingleCRL(cert *x509.Certificate, crlURL string) (status, detail string) {
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Download CRL
	resp, err := client.Get(crlURL)
	if err != nil {
		return "Error", fmt.Sprintf("Failed to download CRL: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "Error", fmt.Sprintf("Failed to read CRL: %v", err)
	}

	// Parse the CRL
	crl, err := x509.ParseCRL(crlBytes)
	if err != nil {
		// Try parsing as PEM if DER parsing fails
		block, _ := pem.Decode(crlBytes)
		if block != nil {
			crl, err = x509.ParseCRL(block.Bytes)
			if err != nil {
				return "Error", fmt.Sprintf("Failed to parse CRL: %v", err)
			}
		} else {
			return "Error", fmt.Sprintf("Failed to parse CRL: %v", err)
		}
	}

	// Check if the CRL is expired
	if crl.TBSCertList.NextUpdate.Before(time.Now()) {
		return "Warning", "CRL is expired"
	}

	// Check if the certificate is in the CRL
	for _, revokedCert := range crl.TBSCertList.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			reason := "unspecified"
			for _, ext := range revokedCert.Extensions {
				if ext.Id.Equal([]int{2, 5, 29, 21}) { // OID for CRL reason
					reason = parseCRLReason(ext.Value[0])
					break
				}
			}
			return "Revoked", fmt.Sprintf("Certificate was revoked on %s. Reason: %s",
				revokedCert.RevocationTime.Format(time.RFC3339),
				reason)
		}
	}

	return "Valid", "Certificate is not revoked"
}

// parseCRLReason converts a CRL reason code to a human-readable string
func parseCRLReason(reason byte) string {
	reasons := map[byte]string{
		0:  "unspecified",
		1:  "keyCompromise",
		2:  "cACompromise",
		3:  "affiliationChanged",
		4:  "superseded",
		5:  "cessationOfOperation",
		6:  "certificateHold",
		8:  "removeFromCRL",
		9:  "privilegeWithdrawn",
		10: "aACompromise",
	}

	if str, ok := reasons[reason]; ok {
		return str
	}
	return "unknown"
}

// validateChain performs comprehensive chain validation and expiration checks
func validateChain(certs []*x509.Certificate) struct {
	IsValid       bool   `json:"isValid"`
	ErrorMessage  string `json:"errorMessage,omitempty"`
	ExpiresIn     int    `json:"expiresIn"`
	NextExpiry    string `json:"nextExpiry"`
	ExpiryWarning string `json:"expiryWarning"`
} {
	result := struct {
		IsValid       bool   `json:"isValid"`
		ErrorMessage  string `json:"errorMessage,omitempty"`
		ExpiresIn     int    `json:"expiresIn"`
		NextExpiry    string `json:"nextExpiry"`
		ExpiryWarning string `json:"expiryWarning"`
	}{
		IsValid:   true,
		ExpiresIn: 365, // Default to a year if no certificates
	}

	if len(certs) == 0 {
		result.IsValid = false
		result.ErrorMessage = "No certificates in chain"
		return result
	}

	// Create intermediate cert pool
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs)-1; i++ {
		intermediates.AddCert(certs[i])
	}

	// Create root cert pool
	roots := x509.NewCertPool()
	if len(certs) > 1 {
		roots.AddCert(certs[len(certs)-1])
	}

	// Verify the chain
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   time.Now(),
	}

	if _, err := certs[0].Verify(opts); err != nil {
		result.IsValid = false
		result.ErrorMessage = fmt.Sprintf("Chain validation failed: %v", err)
	}

	// Check expiration for all certificates
	now := time.Now()
	minDays := math.MaxInt32
	var nextToExpire string

	for i, cert := range certs {
		if now.After(cert.NotBefore) && now.After(cert.NotAfter) {
			result.IsValid = false
			result.ErrorMessage = fmt.Sprintf("Certificate %d has expired", i+1)
			continue
		}

		if now.Before(cert.NotBefore) {
			result.IsValid = false
			result.ErrorMessage = fmt.Sprintf("Certificate %d is not yet valid", i+1)
			continue
		}

		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
		if daysUntilExpiry < minDays {
			minDays = daysUntilExpiry
			nextToExpire = formatCertName(cert, i, len(certs))
		}
	}

	result.ExpiresIn = minDays
	result.NextExpiry = nextToExpire

	// Set expiry warning based on time remaining
	if minDays <= 0 {
		result.ExpiryWarning = "Certificate has expired!"
	} else if minDays <= 7 {
		result.ExpiryWarning = fmt.Sprintf("Critical: Certificate expires in %d days!", minDays)
	} else if minDays <= 30 {
		result.ExpiryWarning = fmt.Sprintf("Warning: Certificate expires in %d days", minDays)
	} else if minDays <= 90 {
		result.ExpiryWarning = fmt.Sprintf("Notice: Certificate expires in %d days", minDays)
	}

	return result
}

// formatCertName returns a human-readable name for the certificate
func formatCertName(cert *x509.Certificate, index, total int) string {
	if index == 0 {
		return "Server Certificate"
	}
	if index == total-1 {
		return "Root CA"
	}
	return fmt.Sprintf("Intermediate CA %d", index)
}
