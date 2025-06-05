package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/s0undy/megadunder/internal/api/models"
)

type IPLookupHandler struct{}

func NewIPLookupHandler() *IPLookupHandler {
	return &IPLookupHandler{}
}

func (h *IPLookupHandler) Handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.IPLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, "Invalid request format")
		return
	}

	// Validate request
	if req.Query == "" {
		h.sendError(w, "Query cannot be empty")
		return
	}

	// Normalize query
	req.Query = strings.TrimSpace(req.Query)
	req.Query = strings.ToUpper(req.Query) // AS numbers are typically uppercase

	// Determine the appropriate database if auto is selected
	if req.Database == "auto" {
		req.Database = h.determineDatabase(req.Query)
	}

	// Perform the lookup
	response, err := h.performLookup(req)
	if err != nil {
		h.sendError(w, err.Error())
		return
	}

	h.sendResponse(w, response)
}

func (h *IPLookupHandler) determineDatabase(query string) string {
	// AS number pattern
	asPattern := regexp.MustCompile(`^AS\d+$`)
	if asPattern.MatchString(query) {
		return "ripe" // Default to RIPE for AS lookups, they have good global coverage
	}

	// IPv4 pattern
	ipv4Pattern := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$`)
	if ipv4Pattern.MatchString(query) {
		// Extract first octet
		firstOctet := strings.Split(query, ".")[0]
		switch firstOctet {
		case "1", "27", "43", "58", "59", "60", "61", "101", "103", "106", "110", "111", "112", "113", "114", "115", "116", "117", "118", "119", "120", "121", "122", "123", "124", "125":
			return "apnic"
		case "24", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "96", "97", "98", "99", "100", "104", "107", "108", "128", "129", "130", "131", "132", "134", "135", "136", "137", "138", "139", "140", "142", "143", "144", "146", "147", "148", "149", "152", "155", "156", "157", "158", "159", "160", "161", "162", "164", "165", "166", "167", "168", "169", "170", "171", "172", "173", "174", "184", "192", "198", "199":
			return "arin"
		case "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "109", "141", "145", "151", "176", "178", "185", "188", "193", "194", "195":
			return "ripe"
		default:
			return "ripe" // Default to RIPE if we can't determine
		}
	}

	// IPv6 pattern (simplified)
	ipv6Pattern := regexp.MustCompile(`^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$`)
	if ipv6Pattern.MatchString(query) {
		return "ripe" // Default to RIPE for IPv6
	}

	return "ripe" // Default to RIPE if we can't determine
}

func (h *IPLookupHandler) performLookup(lookupReq models.IPLookupRequest) (*models.IPLookupResponse, error) {
	var baseURL string
	var queryParams url.Values

	switch lookupReq.Database {
	case "ripe":
		baseURL = "https://rest.db.ripe.net/search"
		queryParams = url.Values{
			"query-string": {lookupReq.Query},
			"flags":        {"no-filtering"},
			"source":       {"RIPE"},
		}
	case "arin":
		baseURL = "https://whois.arin.net/rest/ip/" + lookupReq.Query
		queryParams = url.Values{
			"showDetails": {"true"},
		}
	case "apnic":
		baseURL = "https://wq.apnic.net/whois-search/static/search.html"
		queryParams = url.Values{
			"searchtext": {lookupReq.Query},
		}
	default:
		return nil, fmt.Errorf("unsupported database: %s", lookupReq.Database)
	}

	// Build the URL
	apiURL := fmt.Sprintf("%s?%s", baseURL, queryParams.Encode())

	// Make the request
	client := &http.Client{}
	httpReq, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	// Set appropriate headers based on the database
	switch lookupReq.Database {
	case "ripe":
		httpReq.Header.Set("Accept", "application/json")
	case "arin":
		httpReq.Header.Set("Accept", "application/json")
	case "apnic":
		httpReq.Header.Set("Accept", "application/json")
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	// Parse the response based on the database
	return h.parseResponse(lookupReq.Database, body)
}

func (h *IPLookupHandler) parseResponse(database string, body []byte) (*models.IPLookupResponse, error) {
	response := &models.IPLookupResponse{
		Source:      database,
		BasicInfo:   make(map[string]string),
		NetworkInfo: make(map[string]any),
		ContactInfo: make(map[string]any),
		RawResponse: string(body),
	}

	// Parse the response based on the database format
	switch database {
	case "ripe":
		return h.parseRIPEResponse(body, response)
	case "arin":
		return h.parseARINResponse(body, response)
	case "apnic":
		return h.parseAPNICResponse(body, response)
	default:
		return nil, fmt.Errorf("unsupported database format: %s", database)
	}
}

func (h *IPLookupHandler) parseRIPEResponse(body []byte, response *models.IPLookupResponse) (*models.IPLookupResponse, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing RIPE response: %v", err)
	}

	// Extract basic information
	if objects, ok := result["objects"].(map[string]interface{}); ok {
		if object, ok := objects["object"].([]interface{}); ok && len(object) > 0 {
			if firstObj, ok := object[0].(map[string]interface{}); ok {
				response.BasicInfo["type"] = fmt.Sprint(firstObj["type"])
				response.BasicInfo["name"] = fmt.Sprint(firstObj["name"])
				if attrs, ok := firstObj["attributes"].(map[string]interface{}); ok {
					if attrList, ok := attrs["attribute"].([]interface{}); ok {
						for _, attr := range attrList {
							if a, ok := attr.(map[string]interface{}); ok {
								name := fmt.Sprint(a["name"])
								value := fmt.Sprint(a["value"])
								switch name {
								case "country":
									response.BasicInfo["country"] = value
								case "org":
									response.BasicInfo["organization"] = value
								case "admin-c", "tech-c":
									if contacts, ok := response.ContactInfo[name]; ok {
										if contactList, ok := contacts.([]string); ok {
											response.ContactInfo[name] = append(contactList, value)
										}
									} else {
										response.ContactInfo[name] = []string{value}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return response, nil
}

func (h *IPLookupHandler) parseARINResponse(body []byte, response *models.IPLookupResponse) (*models.IPLookupResponse, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing ARIN response: %v", err)
	}

	// Extract information from ARIN's format
	if net, ok := result["net"].(map[string]interface{}); ok {
		response.BasicInfo["name"] = fmt.Sprint(net["name"])
		response.BasicInfo["organization"] = fmt.Sprint(net["orgRef"].(map[string]interface{})["name"])

		if handle, ok := net["handle"].(string); ok {
			response.BasicInfo["handle"] = handle
		}

		if netBlocks, ok := net["netBlocks"].(map[string]interface{}); ok {
			if blocks, ok := netBlocks["netBlock"].([]interface{}); ok && len(blocks) > 0 {
				if block, ok := blocks[0].(map[string]interface{}); ok {
					response.NetworkInfo["cidr"] = fmt.Sprint(block["cidrLength"])
					response.NetworkInfo["type"] = fmt.Sprint(block["type"])
				}
			}
		}
	}

	return response, nil
}

func (h *IPLookupHandler) parseAPNICResponse(body []byte, response *models.IPLookupResponse) (*models.IPLookupResponse, error) {
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("error parsing APNIC response: %v", err)
	}

	// Extract information from APNIC's format
	if objects, ok := result["objects"].([]interface{}); ok && len(objects) > 0 {
		for _, obj := range objects {
			if object, ok := obj.(map[string]interface{}); ok {
				switch object["type"] {
				case "inetnum", "inet6num":
					response.BasicInfo["type"] = "IP"
					response.BasicInfo["range"] = fmt.Sprint(object["primary"])
				case "aut-num":
					response.BasicInfo["type"] = "AS"
					response.BasicInfo["number"] = fmt.Sprint(object["primary"])
				}

				if attrs, ok := object["attributes"].([]interface{}); ok {
					for _, attr := range attrs {
						if a, ok := attr.(map[string]interface{}); ok {
							name := fmt.Sprint(a["name"])
							value := fmt.Sprint(a["value"])
							switch name {
							case "country":
								response.BasicInfo["country"] = value
							case "descr":
								response.BasicInfo["description"] = value
							case "admin-c", "tech-c":
								if contacts, ok := response.ContactInfo[name]; ok {
									if contactList, ok := contacts.([]string); ok {
										response.ContactInfo[name] = append(contactList, value)
									}
								} else {
									response.ContactInfo[name] = []string{value}
								}
							}
						}
					}
				}
			}
		}
	}

	return response, nil
}

func (h *IPLookupHandler) sendError(w http.ResponseWriter, message string) {
	response := models.IPLookupResponse{
		Error: message,
	}
	h.sendResponse(w, &response)
}

func (h *IPLookupHandler) sendResponse(w http.ResponseWriter, response *models.IPLookupResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
