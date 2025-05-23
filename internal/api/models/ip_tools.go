package models

// IPToolsRequest represents the incoming request for IP tools
type IPToolsRequest struct {
	IPVersion   string      `json:"ipVersion"`
	IPAddress   string      `json:"ipAddress"`
	Command     string      `json:"command"`
	CurlOptions CurlOptions `json:"curlOptions,omitempty"`
}

// CurlOptions represents curl-specific options
type CurlOptions struct {
	Protocol string `json:"protocol"` // "http" or "https"
	Port     string `json:"port,omitempty"`
}

// IPToolsResponse represents the response from IP tools
type IPToolsResponse struct {
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}
