package reporter

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"idorplus/pkg/fuzzer"
)

func TestGenerateReportPermissions(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "reporter_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	reportPath := filepath.Join(tmpDir, "report.json")

	// Initialize reporter and add a finding
	r := NewReporter("json")
	r.AddFinding(&fuzzer.FuzzResult{
		Job: &fuzzer.FuzzJob{
			URL:     "http://example.com/api/users/1",
			Method:  "GET",
			Payload: "1",
		},
		StatusCode: 200,
		ContentLen: 123,
		Duration:   100 * time.Millisecond,
		Evidence:   "Sensitive Data",
	})

	// Generate report
	if err := r.GenerateReport(reportPath); err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("Failed to stat report file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Expected file permissions 0600 (rw-------), got %04o", mode)
	}
}

func TestGenerateMarkdownReportPermissions(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, err := os.MkdirTemp("", "reporter_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	reportPath := filepath.Join(tmpDir, "report.md")

	// Initialize reporter and add a finding
	r := NewReporter("markdown")
	r.AddFinding(&fuzzer.FuzzResult{
		Job: &fuzzer.FuzzJob{
			URL:     "http://example.com/api/users/1",
			Method:  "GET",
			Payload: "1",
		},
		StatusCode: 200,
		ContentLen: 123,
		Duration:   100 * time.Millisecond,
		Evidence:   "Sensitive Data",
	})

	// Generate report
	if err := r.GenerateReport(reportPath); err != nil {
		t.Fatalf("GenerateReport failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(reportPath)
	if err != nil {
		t.Fatalf("Failed to stat report file: %v", err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("Expected file permissions 0600 (rw-------), got %04o", mode)
	}
}
