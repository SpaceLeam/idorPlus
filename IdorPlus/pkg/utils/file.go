package utils

import "os"

// WriteFile writes content to a file
func WriteFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}
