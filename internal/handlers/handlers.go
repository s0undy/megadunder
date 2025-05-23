package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
)

type Handler struct {
	tmpl *template.Template
}

func NewHandler(tmpl *template.Template) *Handler {
	return &Handler{tmpl: tmpl}
}

type PageData struct {
	Title  string
	Active string
}

func (h *Handler) IndexHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:  "Home",
		Active: "home",
	}
	h.tmpl.ExecuteTemplate(w, "layout.html", data)
}

func (h *Handler) IPToolsHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:  "IP Tools",
		Active: "ip",
	}
	h.tmpl.ExecuteTemplate(w, "layout.html", data)
}

func (h *Handler) DNSToolsHandler(w http.ResponseWriter, r *http.Request) {
	data := PageData{
		Title:  "DNS Tools",
		Active: "dns",
	}
	h.tmpl.ExecuteTemplate(w, "layout.html", data)
}

type IPToolsRequest struct {
	IPVersion   string `json:"ipVersion"`
	IPAddress   string `json:"ipAddress"`
	Command     string `json:"command"`
	CurlOptions struct {
		Protocol string `json:"protocol"`
		Port     string `json:"port"`
	} `json:"curlOptions"`
}

type DNSToolsRequest struct {
	RecordType string `json:"recordType"`
	Name       string `json:"name"`
}

type Response struct {
	Error  string `json:"error,omitempty"`
	Output string `json:"output"`
}

func (h *Handler) IPToolsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req IPToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Execute the command based on the request
	// This is where you would call your existing command execution logic
	output := "Command output will appear here..."

	resp := Response{Output: output}
	json.NewEncoder(w).Encode(resp)
}

func (h *Handler) DNSToolsAPIHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req DNSToolsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Execute the DNS lookup based on the request
	// This is where you would call your existing DNS lookup logic
	output := "DNS lookup results will appear here..."

	resp := Response{Output: output}
	json.NewEncoder(w).Encode(resp)
}
