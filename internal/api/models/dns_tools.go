package models

// DNSLookupRequest represents the incoming request for DNS lookups
type DNSLookupRequest struct {
	RecordType string `json:"recordType"`
	Name       string `json:"name"`
}

// DNSLookupResponse represents the response from DNS lookups
type DNSLookupResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}
