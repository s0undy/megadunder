package models

// MailToolsRequest represents the incoming request for mail tools
type MailToolsRequest struct {
	Domain       string      `json:"domain"`
	CheckType    string      `json:"checkType"`
	DKIMSelector string      `json:"dkimSelector,omitempty"`
	SMTPOptions  SMTPOptions `json:"smtpOptions,omitempty"`
}

// SMTPOptions represents SMTP-specific test options
type SMTPOptions struct {
	Port     string `json:"port"`
	CheckTLS bool   `json:"checkTLS"`
}

// MailToolsResponse represents the response from mail tools
type MailToolsResponse struct {
	Output    string     `json:"output"`
	Error     string     `json:"error,omitempty"`
	SPFInfo   *CheckInfo `json:"spfInfo,omitempty"`
	DMARCInfo *CheckInfo `json:"dmarcInfo,omitempty"`
	DKIMInfo  *CheckInfo `json:"dkimInfo,omitempty"`
	MXInfo    *CheckInfo `json:"mxInfo,omitempty"`
	SMTPInfo  *CheckInfo `json:"smtpInfo,omitempty"`
}

// CheckInfo represents the status and details of a specific check
type CheckInfo struct {
	Status  string   `json:"status"`  // "valid", "warning", "error"
	Title   string   `json:"title"`   // Display title
	Message string   `json:"message"` // Main status message
	Details []string `json:"details"` // Additional details
}
