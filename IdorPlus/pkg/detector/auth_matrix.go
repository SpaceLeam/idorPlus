package detector

import (
	"fmt"
	"sync"

	"idorplus/pkg/client"

	"github.com/pterm/pterm"
)

// AuthMatrixTester performs authorization matrix testing
// Tests: User A with User A session, User A with User B session, etc.
type AuthMatrixTester struct {
	client   *client.SmartClient
	sessions map[string]string // name -> cookie string
	mu       sync.RWMutex
}

// MatrixResult contains the results of auth matrix testing
type MatrixResult struct {
	Endpoint     string
	Method       string
	Results      map[string]*SessionResult
	IsVulnerable bool
	Reason       string
}

// SessionResult contains the result for a specific session
type SessionResult struct {
	SessionName string
	StatusCode  int
	ContentLen  int
	HasAccess   bool
	Response    []byte
}

// NewAuthMatrixTester creates a new auth matrix tester
func NewAuthMatrixTester(c *client.SmartClient) *AuthMatrixTester {
	return &AuthMatrixTester{
		client:   c,
		sessions: make(map[string]string),
	}
}

// AddSession adds a session for testing
func (amt *AuthMatrixTester) AddSession(name, cookies string) {
	amt.mu.Lock()
	defer amt.mu.Unlock()
	amt.sessions[name] = cookies
	amt.client.GetSessionManager().AddSession(name, cookies)
}

// TestEndpoint tests authorization on a specific endpoint
func (amt *AuthMatrixTester) TestEndpoint(url, method string) *MatrixResult {
	amt.mu.RLock()
	defer amt.mu.RUnlock()

	result := &MatrixResult{
		Endpoint: url,
		Method:   method,
		Results:  make(map[string]*SessionResult),
	}

	// Test with each session
	for name := range amt.sessions {
		sessionResult := amt.testWithSession(url, method, name)
		result.Results[name] = sessionResult
	}

	// Test without any session
	noSessionResult := amt.testWithoutSession(url, method)
	result.Results["no_session"] = noSessionResult

	// Analyze results for IDOR
	result.IsVulnerable, result.Reason = amt.analyzeMatrix(result.Results)

	return result
}

// testWithSession tests endpoint with a specific session
func (amt *AuthMatrixTester) testWithSession(url, method, sessionName string) *SessionResult {
	session := amt.client.GetSessionManager().GetSession(sessionName)
	if session == nil {
		return &SessionResult{
			SessionName: sessionName,
			HasAccess:   false,
		}
	}

	req := amt.client.Request()

	// Add session cookies
	for _, cookie := range session.Cookies {
		req.SetCookie(cookie)
	}

	// Execute request
	var resp interface {
		StatusCode() int
		Body() []byte
	}
	var err error

	switch method {
	case "POST":
		r, e := req.Post(url)
		resp, err = r, e
	case "PUT":
		r, e := req.Put(url)
		resp, err = r, e
	case "DELETE":
		r, e := req.Delete(url)
		resp, err = r, e
	case "PATCH":
		r, e := req.Patch(url)
		resp, err = r, e
	default:
		r, e := req.Get(url)
		resp, err = r, e
	}

	if err != nil {
		return &SessionResult{
			SessionName: sessionName,
			HasAccess:   false,
		}
	}

	hasAccess := resp.StatusCode() >= 200 && resp.StatusCode() < 300

	return &SessionResult{
		SessionName: sessionName,
		StatusCode:  resp.StatusCode(),
		ContentLen:  len(resp.Body()),
		HasAccess:   hasAccess,
		Response:    resp.Body(),
	}
}

// testWithoutSession tests endpoint without any authentication
func (amt *AuthMatrixTester) testWithoutSession(url, method string) *SessionResult {
	req := amt.client.Request()

	// Execute request without cookies
	var resp interface {
		StatusCode() int
		Body() []byte
	}
	var err error

	switch method {
	case "POST":
		r, e := req.Post(url)
		resp, err = r, e
	case "PUT":
		r, e := req.Put(url)
		resp, err = r, e
	case "DELETE":
		r, e := req.Delete(url)
		resp, err = r, e
	case "PATCH":
		r, e := req.Patch(url)
		resp, err = r, e
	default:
		r, e := req.Get(url)
		resp, err = r, e
	}

	if err != nil {
		return &SessionResult{
			SessionName: "no_session",
			HasAccess:   false,
		}
	}

	hasAccess := resp.StatusCode() >= 200 && resp.StatusCode() < 300

	return &SessionResult{
		SessionName: "no_session",
		StatusCode:  resp.StatusCode(),
		ContentLen:  len(resp.Body()),
		HasAccess:   hasAccess,
		Response:    resp.Body(),
	}
}

// analyzeMatrix analyzes the results to detect IDOR
func (amt *AuthMatrixTester) analyzeMatrix(results map[string]*SessionResult) (bool, string) {
	// Find the "owner" session (first session added, assumed to be the resource owner)
	var ownerResult *SessionResult
	var ownerName string
	for name, r := range results {
		if name != "no_session" {
			ownerResult = r
			ownerName = name
			break
		}
	}

	if ownerResult == nil {
		return false, ""
	}

	// Check if other sessions can access what they shouldn't
	for name, r := range results {
		if name == ownerName {
			continue
		}

		// If owner has access but this session also has access
		if ownerResult.HasAccess && r.HasAccess {
			// This could be IDOR if it's a different user accessing owner's resource
			if name == "no_session" {
				return true, "Unauthenticated access to protected resource"
			}

			// Compare content length - if similar, likely same data
			lenDiff := abs(ownerResult.ContentLen - r.ContentLen)
			if lenDiff < 50 || float64(lenDiff)/float64(ownerResult.ContentLen) < 0.1 {
				return true, fmt.Sprintf("Session '%s' can access '%s' resource", name, ownerName)
			}
		}
	}

	return false, ""
}

// PrintMatrix prints the authorization matrix as a table
func (amt *AuthMatrixTester) PrintMatrix(result *MatrixResult) {
	pterm.DefaultSection.Printf("Auth Matrix: %s %s\n", result.Method, result.Endpoint)

	tableData := pterm.TableData{
		{"Session", "Status", "Content Length", "Access"},
	}

	for name, r := range result.Results {
		accessStr := pterm.Red("DENIED")
		if r.HasAccess {
			accessStr = pterm.Green("GRANTED")
		}

		tableData = append(tableData, []string{
			name,
			fmt.Sprintf("%d", r.StatusCode),
			fmt.Sprintf("%d", r.ContentLen),
			accessStr,
		})
	}

	pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

	if result.IsVulnerable {
		pterm.Error.Printf("IDOR DETECTED: %s\n", result.Reason)
	} else {
		pterm.Success.Println("No IDOR detected for this endpoint")
	}
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
