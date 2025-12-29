package utils

import (
	"crypto/rand"
	"math/big"
	"os"
	"strings"
)

// RandomString generates a cryptographically secure random string
func RandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		b[i] = letters[num.Int64()]
	}
	return string(b)
}

// ExtractIDFromURL extracts the last path segment as an ID
func ExtractIDFromURL(url string) string {
	// Remove query string
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}
	// Remove trailing slash
	url = strings.TrimSuffix(url, "/")
	// Get last segment
	parts := strings.Split(url, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// SanitizeFilename removes unsafe characters from filename
func SanitizeFilename(name string) string {
	unsafe := []string{"/", "\\", ":", "*", "?", "\"", "<", ">", "|", "\n", "\r"}
	for _, char := range unsafe {
		name = strings.ReplaceAll(name, char, "_")
	}
	return name
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// LoadWordlist loads a wordlist from file
func LoadWordlist(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var payloads []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}
	return payloads, nil
}

// UniqueStrings returns unique strings from a slice
func UniqueStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range input {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

// ContainsString checks if a string is in a slice
func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// TruncateString truncates a string to a max length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// ParseCookieString parses a cookie string into key-value pairs
func ParseCookieString(cookieStr string) map[string]string {
	cookies := make(map[string]string)
	parts := strings.Split(cookieStr, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			cookies[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	return cookies
}
