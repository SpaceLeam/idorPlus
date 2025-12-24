package utils

import "os"

// WriteFile writes content to a file with secure permissions (0600)
func WriteFile(path string, data []byte) error {
	// Use 0600 permissions: read/write only by owner
	return os.WriteFile(path, data, 0600)
}
