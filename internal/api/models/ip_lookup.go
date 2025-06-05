package models

// IPLookupRequest represents a request to lookup IP or AS information
type IPLookupRequest struct {
	Query    string `json:"query"`    // IP address or AS number
	Database string `json:"database"` // "auto", "ripe", "arin", or "apnic"
}

// IPLookupResponse represents the response from an IP or AS lookup
type IPLookupResponse struct {
	BasicInfo   map[string]string `json:"basicInfo,omitempty"`
	NetworkInfo map[string]any    `json:"networkInfo,omitempty"`
	ContactInfo map[string]any    `json:"contactInfo,omitempty"`
	RawResponse string            `json:"rawResponse,omitempty"`
	Error       string            `json:"error,omitempty"`
	Source      string            `json:"source,omitempty"` // Which database provided the response
}

// BasicInfo fields for different types of responses
type BasicInfo struct {
	Type         string `json:"type"`           // "IP" or "AS"
	Value        string `json:"value"`          // The IP address or AS number
	Name         string `json:"name,omitempty"` // Network name or AS name
	Country      string `json:"country,omitempty"`
	Organization string `json:"organization,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Source       string `json:"source"` // Which RIR provided the data
}

// NetworkInfo fields for IP addresses
type NetworkInfo struct {
	CIDR          string   `json:"cidr,omitempty"`
	Range         []string `json:"range,omitempty"`
	PrefixLength  int      `json:"prefix_length,omitempty"`
	ASN           string   `json:"asn,omitempty"`
	ASName        string   `json:"as_name,omitempty"`
	Status        string   `json:"status,omitempty"`
	DNSReverse    []string `json:"dns_reverse,omitempty"`
	Route         []string `json:"route,omitempty"`
	ParentNetwork string   `json:"parent_network,omitempty"`
}

// ContactInfo fields
type ContactInfo struct {
	Admin     []string `json:"admin,omitempty"`
	Tech      []string `json:"tech,omitempty"`
	Abuse     []string `json:"abuse,omitempty"`
	NOC       []string `json:"noc,omitempty"`
	RTR       []string `json:"rtr,omitempty"`
	Registrar string   `json:"registrar,omitempty"`
}
