package utils

import "os"

// WriteFile writes content to a file
func WriteFile(path string, data []byte) error {
	// Security: Use 0600 permissions to restrict access to the file owner
	return os.WriteFile(path, data, 0600)
}
