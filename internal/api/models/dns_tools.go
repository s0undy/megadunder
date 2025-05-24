package models

// DNSLookupRequest represents the incoming request for DNS lookups
type DNSLookupRequest struct {
	RecordType  string `json:"recordType"`
	Name        string `json:"name"`
	CheckDNSSEC bool   `json:"checkDNSSEC"`
}

// DNSLookupResponse represents the response from DNS lookups
type DNSLookupResponse struct {
	Output     string      `json:"output"`
	Error      string      `json:"error,omitempty"`
	DNSSECInfo *DNSSECInfo `json:"dnssecInfo,omitempty"`
}

// DNSSECInfo contains DNSSEC validation results
type DNSSECInfo struct {
	Enabled           bool   `json:"enabled"`
	Status            string `json:"status"`
	Validated         bool   `json:"validated"`
	HasDS             bool   `json:"hasDS"`
	DSRecords         string `json:"dsRecords,omitempty"`
	SignatureInfo     string `json:"signatureInfo,omitempty"`
	ValidationDetails string `json:"validationDetails,omitempty"`
	Error             string `json:"error,omitempty"`
}
