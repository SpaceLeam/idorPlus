package crawler

import (
	"regexp"
)

type JSParser struct {
	// Parse JavaScript files to extract API endpoints
}

func NewJSParser() *JSParser {
	return &JSParser{}
}

func (jp *JSParser) ParseJS(jsContent string) []string {
	// Regex patterns for API endpoints
	// Extract: /api/users/123, /v1/orders/{id}
	patterns := []string{
		`["'](/api/[a-zA-Z0-9/_-]+)["']`,
		`["'](/v\d+/[a-zA-Z0-9/_-]+)["']`,
		`baseURL\s*[+:]\s*["']([^"']+)["']`,
		`["'](/[a-zA-Z0-9/_-]+/[a-zA-Z0-9/_-]+)["']`, // Generic path
	}

	var endpoints []string
	seen := make(map[string]bool)

	for _, p := range patterns {
		re := regexp.MustCompile(p)
		matches := re.FindAllStringSubmatch(jsContent, -1)
		for _, match := range matches {
			if len(match) > 1 {
				endpoint := match[1]
				if !seen[endpoint] {
					endpoints = append(endpoints, endpoint)
					seen[endpoint] = true
				}
			}
		}
	}
	return endpoints
}
