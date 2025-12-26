package utils

import "os"

// WriteFile writes content to a file with secure permissions (0600)
// This ensures that the file is only readable and writable by the owner
func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}
