package crawler

import (
	"regexp"
	"strings"
	"sync"
)

// ShadowAPIDiscoverer discovers hidden/undocumented API endpoints
type ShadowAPIDiscoverer struct {
	foundEndpoints map[string]EndpointInfo
	mu             sync.Mutex
}

// EndpointInfo contains details about a discovered endpoint
type EndpointInfo struct {
	URL        string
	Method     string
	Source     string
	HasParams  bool
	ParamNames []string
	IsInternal bool
}

// NewShadowAPIDiscoverer creates a new discoverer
func NewShadowAPIDiscoverer() *ShadowAPIDiscoverer {
	return &ShadowAPIDiscoverer{
		foundEndpoints: make(map[string]EndpointInfo),
	}
}

// ExtractFromJS extracts API endpoints from JavaScript content
func (s *ShadowAPIDiscoverer) ExtractFromJS(content, sourceURL string) []EndpointInfo {
	var endpoints []EndpointInfo

	// Pattern collection for modern JS frameworks
	patterns := []*regexp.Regexp{
		// Fetch API
		regexp.MustCompile(`fetch\s*\(\s*['"]([^'"]+)['"]`),
		// Axios
		regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`),
		// jQuery AJAX
		regexp.MustCompile(`\$\.(ajax|get|post)\s*\(\s*['"]?([^'"\s,]+)`),
		regexp.MustCompile(`url\s*:\s*['"]([^'"]+)['"]`),
		// XMLHttpRequest
		regexp.MustCompile(`\.open\s*\(\s*['"](\w+)['"]\s*,\s*['"]([^'"]+)['"]`),
		// String literals with API patterns
		regexp.MustCompile(`['"](/api/[^'"]+)['"]`),
		regexp.MustCompile(`['"](/v[0-9]+/[^'"]+)['"]`),
		regexp.MustCompile(`['"](/graphql[^'"]*)['"]`),
		// REST endpoints
		regexp.MustCompile(`['"]((?:https?://)?[^'"]+/(?:users|accounts|orders|products|items|resources|data|admin|internal|private|debug)[^'"]*)['"]`),
		// Endpoint objects/configs
		regexp.MustCompile(`(?:endpoint|url|path|route|api)\s*[:=]\s*['"]([^'"]+)['"]`),
		// WebSocket endpoints
		regexp.MustCompile(`(?:wss?|WebSocket)\s*\(\s*['"]([^'"]+)['"]`),
	}

	// Extract using all patterns
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				url := match[len(match)-1]
				method := "GET"

				ep := s.createEndpointInfo(url, method, sourceURL)
				if ep != nil {
					endpoints = append(endpoints, *ep)
					s.addEndpoint(*ep)
				}
			}
		}
	}

	return endpoints
}

// ExtractFromHTML extracts endpoints from HTML content
func (s *ShadowAPIDiscoverer) ExtractFromHTML(content, sourceURL string) []EndpointInfo {
	var endpoints []EndpointInfo

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`<form[^>]*action=["']([^"']+)["']`),
		regexp.MustCompile(`data-(?:url|endpoint|api|src)=["']([^"']+)["']`),
		regexp.MustCompile(`href=["']([^"']*(?:api|graphql|v[0-9])[^"']*)["']`),
		regexp.MustCompile(`<script[^>]*src=["']([^"']+\.js[^"']*)["']`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				ep := s.createEndpointInfo(match[1], "GET", sourceURL)
				if ep != nil {
					endpoints = append(endpoints, *ep)
					s.addEndpoint(*ep)
				}
			}
		}
	}

	return endpoints
}

// ExtractFromJSON extracts endpoints from JSON/API responses
func (s *ShadowAPIDiscoverer) ExtractFromJSON(content, sourceURL string) []EndpointInfo {
	var endpoints []EndpointInfo

	urlPattern := regexp.MustCompile(`"(?:url|href|link|endpoint|path|uri)":\s*"([^"]+)"`)
	matches := urlPattern.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) >= 2 {
			ep := s.createEndpointInfo(match[1], "GET", sourceURL)
			if ep != nil {
				endpoints = append(endpoints, *ep)
				s.addEndpoint(*ep)
			}
		}
	}

	return endpoints
}

func (s *ShadowAPIDiscoverer) createEndpointInfo(url, method, source string) *EndpointInfo {
	if url == "" || len(url) < 2 {
		return nil
	}

	skipPatterns := []string{
		".css", ".png", ".jpg", ".gif", ".svg", ".ico",
		".woff", ".ttf", "font", "image", "static",
		"javascript:", "mailto:", "#",
	}

	for _, skip := range skipPatterns {
		if strings.Contains(strings.ToLower(url), skip) {
			return nil
		}
	}

	ep := &EndpointInfo{
		URL:    url,
		Method: method,
		Source: source,
	}

	if strings.Contains(url, "?") || strings.Contains(url, "{") {
		ep.HasParams = true
		ep.ParamNames = extractParamNames(url)
	}

	internalPatterns := []string{"internal", "admin", "debug", "private", "test", "dev", "staging"}
	for _, p := range internalPatterns {
		if strings.Contains(strings.ToLower(url), p) {
			ep.IsInternal = true
			break
		}
	}

	return ep
}

func (s *ShadowAPIDiscoverer) addEndpoint(ep EndpointInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := ep.Method + ":" + ep.URL
	if _, exists := s.foundEndpoints[key]; !exists {
		s.foundEndpoints[key] = ep
	}
}

// GetAllEndpoints returns all discovered endpoints
func (s *ShadowAPIDiscoverer) GetAllEndpoints() []EndpointInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	endpoints := make([]EndpointInfo, 0, len(s.foundEndpoints))
	for _, ep := range s.foundEndpoints {
		endpoints = append(endpoints, ep)
	}
	return endpoints
}

// GetInternalEndpoints returns only internal/admin endpoints
func (s *ShadowAPIDiscoverer) GetInternalEndpoints() []EndpointInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	var internal []EndpointInfo
	for _, ep := range s.foundEndpoints {
		if ep.IsInternal {
			internal = append(internal, ep)
		}
	}
	return internal
}

// GetEndpointsWithIDParams returns endpoints with ID-like parameters
func (s *ShadowAPIDiscoverer) GetEndpointsWithIDParams() []EndpointInfo {
	s.mu.Lock()
	defer s.mu.Unlock()

	var withID []EndpointInfo
	for _, ep := range s.foundEndpoints {
		for _, param := range ep.ParamNames {
			if isIDParam(param) {
				withID = append(withID, ep)
				break
			}
		}
	}
	return withID
}

func extractParamNames(url string) []string {
	var params []string

	if idx := strings.Index(url, "?"); idx != -1 {
		query := url[idx+1:]
		for _, pair := range strings.Split(query, "&") {
			if name := strings.Split(pair, "=")[0]; name != "" {
				params = append(params, name)
			}
		}
	}

	bracePattern := regexp.MustCompile(`\{([^}]+)\}`)
	for _, match := range bracePattern.FindAllStringSubmatch(url, -1) {
		if len(match) >= 2 {
			params = append(params, match[1])
		}
	}

	colonPattern := regexp.MustCompile(`:(\w+)`)
	for _, match := range colonPattern.FindAllStringSubmatch(url, -1) {
		if len(match) >= 2 {
			params = append(params, match[1])
		}
	}

	return params
}

func isIDParam(param string) bool {
	param = strings.ToLower(param)
	idPatterns := []string{"id", "uid", "uuid", "guid", "key", "token"}
	for _, p := range idPatterns {
		if strings.Contains(param, p) {
			return true
		}
	}
	return false
}
