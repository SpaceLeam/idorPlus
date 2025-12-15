package tests

import (
	"testing"

	"idorplus/pkg/analyzer"
)

func TestIDTypeDetection(t *testing.T) {
	ia := analyzer.NewIdentifierAnalyzer()

	tests := []struct {
		name     string
		input    string
		expected analyzer.IDType
	}{
		{"Numeric simple", "123", analyzer.TypeNumeric},
		{"Numeric long", "9999999999", analyzer.TypeNumeric},
		{"UUID v4", "550e8400-e29b-41d4-a716-446655440000", analyzer.TypeUUID},
		{"UUID v1", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", analyzer.TypeUUID},
		{"MD5 hash", "5d41402abc4b2a76b9719d911017c592", analyzer.TypeMD5},
		{"SHA1 hash", "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", analyzer.TypeSHA1},
		{"Base64 encoded", "dGVzdA==", analyzer.TypeBase64},
		{"Unknown string", "random-string-here", analyzer.TypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ia.DetectType(tt.input)
			if result != tt.expected {
				t.Errorf("DetectType(%s) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIdentifierAnalyzerEmpty(t *testing.T) {
	ia := analyzer.NewIdentifierAnalyzer()

	if result := ia.DetectType(""); result != analyzer.TypeUnknown {
		t.Errorf("Expected TypeUnknown for empty string, got %v", result)
	}
}
