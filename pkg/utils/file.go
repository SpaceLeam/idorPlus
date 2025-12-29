package utils

import "os"

// WriteFile writes content to a file with secure permissions (0600)
func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
