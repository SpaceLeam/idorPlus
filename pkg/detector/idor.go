package detector

import (
	"regexp"
	"strings"

	"idorplus/pkg/analyzer"

	"github.com/go-resty/resty/v2"
)

// IDORDetector detects IDOR vulnerabilities using multiple heuristics
type IDORDetector struct {
	ValidComparator   *analyzer.ResponseComparator // Baseline for valid resource access
	InvalidComparator *analyzer.ResponseComparator // Baseline for invalid/403 response
	Threshold         float64
	CheckPII          bool
	piiPatterns       map[string]*regexp.Regexp
}

// NewIDORDetector creates a new IDOR detector
func NewIDORDetector(validBaseline, invalidBaseline *resty.Response, threshold float64, checkPII bool) *IDORDetector {
	det := &IDORDetector{
		Threshold: threshold,
		CheckPII:  checkPII,
	}

	if validBaseline != nil {
		det.ValidComparator = analyzer.NewResponseComparator(validBaseline)
	}
	if invalidBaseline != nil {
		det.InvalidComparator = analyzer.NewResponseComparator(invalidBaseline)
	}

	// Initialize PII patterns
	det.piiPatterns = map[string]*regexp.Regexp{
		"email":       regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
		"phone_us":    regexp.MustCompile(`\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
		"phone_intl":  regexp.MustCompile(`\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}`),
		"ssn":         regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
		"credit_card": regexp.MustCompile(`\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}`),
		"api_key":     regexp.MustCompile(`(api[_-]?key|apikey|api_secret)["\s:=]+["']?([a-zA-Z0-9_-]{20,})["']?`),
		"jwt":         regexp.MustCompile(`eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`),
		"password":    regexp.MustCompile(`(password|passwd|pwd)["\s:=]+["']?([^"'\s]{4,})["']?`),
		"private_key": regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	}

	return det
}

// Detect checks if a response indicates an IDOR vulnerability
func (d *IDORDetector) Detect(resp *resty.Response) bool {
	if resp == nil {
		return false
	}

	// Heuristic 1: Status code indicates access granted
	statusCode := resp.StatusCode()
	if statusCode >= 200 && statusCode < 300 {
		// Check against invalid baseline
		if d.InvalidComparator != nil {
			invalidBaseline := d.InvalidComparator.Baseline
			// If invalid baseline was 403/401/404 and we got 200, likely IDOR
			if invalidBaseline.StatusCode() == 403 ||
				invalidBaseline.StatusCode() == 401 ||
				invalidBaseline.StatusCode() == 404 {
				return true
			}
		}
	}

	// Heuristic 2: Content similarity check
	if d.ValidComparator != nil {
		comparison := d.ValidComparator.Compare(resp)

		// If response is significantly different from valid baseline
		// AND has successful status code, it might be another user's data
		if comparison.BodySimilarity < d.Threshold && statusCode >= 200 && statusCode < 300 {
			// Additional check: make sure it's not just an error page
			bodyLen := len(resp.Body())
			baselineLen := len(d.ValidComparator.Baseline.Body())

			// If response has substantial content
			if bodyLen > 100 && bodyLen > baselineLen/2 {
				return true
			}
		}
	}

	// Heuristic 3: PII detection
	if d.CheckPII && d.containsPII(resp.Body()) {
		return true
	}

	return false
}

// containsPII checks if response contains personally identifiable information
func (d *IDORDetector) containsPII(body []byte) bool {
	bodyStr := string(body)

	for _, pattern := range d.piiPatterns {
		if pattern.MatchString(bodyStr) {
			return true
		}
	}

	return false
}

// GetPIIMatches returns all PII matches found in the response
func (d *IDORDetector) GetPIIMatches(body []byte) map[string][]string {
	bodyStr := string(body)
	matches := make(map[string][]string)

	for name, pattern := range d.piiPatterns {
		found := pattern.FindAllString(bodyStr, -1)
		if len(found) > 0 {
			matches[name] = found
		}
	}

	return matches
}

// DetectWithEvidence returns detailed detection results
func (d *IDORDetector) DetectWithEvidence(resp *resty.Response) *DetectionResult {
	result := &DetectionResult{
		IsVulnerable: false,
		Reasons:      []string{},
		PIIFound:     make(map[string][]string),
		StatusCode:   resp.StatusCode(),
		ContentLen:   len(resp.Body()),
	}

	// Check status code
	if resp.StatusCode() >= 200 && resp.StatusCode() < 300 {
		if d.InvalidComparator != nil {
			baseline := d.InvalidComparator.Baseline
			if baseline.StatusCode() == 403 || baseline.StatusCode() == 401 {
				result.IsVulnerable = true
				result.Reasons = append(result.Reasons, "Status code bypass: expected 403/401, got 200")
			}
		}
	}

	// Check similarity
	if d.ValidComparator != nil {
		comparison := d.ValidComparator.Compare(resp)
		result.Similarity = comparison.BodySimilarity

		if comparison.BodySimilarity < d.Threshold && resp.StatusCode() >= 200 && resp.StatusCode() < 300 {
			result.IsVulnerable = true
			result.Reasons = append(result.Reasons, "Content significantly different from baseline")
		}
	}

	// Check PII
	if d.CheckPII {
		pii := d.GetPIIMatches(resp.Body())
		if len(pii) > 0 {
			result.IsVulnerable = true
			result.PIIFound = pii
			result.Reasons = append(result.Reasons, "PII detected in response")
		}
	}

	return result
}

// DetectionResult contains detailed information about IDOR detection
type DetectionResult struct {
	IsVulnerable bool
	Reasons      []string
	PIIFound     map[string][]string
	StatusCode   int
	ContentLen   int
	Similarity   float64
}

// IsSoftError checks if the response is a soft 404/error page
func (d *IDORDetector) IsSoftError(resp *resty.Response) bool {
	body := strings.ToLower(string(resp.Body()))

	softErrorIndicators := []string{
		"not found",
		"does not exist",
		"no results",
		"invalid id",
		"resource not found",
		"404",
		"error",
		"unauthorized",
		"access denied",
	}

	for _, indicator := range softErrorIndicators {
		if strings.Contains(body, indicator) {
			return true
		}
	}

	return false
}
