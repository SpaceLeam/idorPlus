package tests

import (
	"testing"

	"idorplus/pkg/generator"
)

func TestNumericGenerator(t *testing.T) {
	ng := generator.NewNumericGenerator()
	payloads := ng.Generate(10)

	// Should have sequential + boundary values
	if len(payloads) < 10 {
		t.Errorf("Expected at least 10 payloads, got %d", len(payloads))
	}

	// Check first few are sequential
	expectedStart := []string{"1", "2", "3", "4", "5"}
	for i, expected := range expectedStart {
		if payloads[i] != expected {
			t.Errorf("Expected payload[%d] = %s, got %s", i, expected, payloads[i])
		}
	}

	// Check boundary values are included
	boundaries := []string{"0", "-1", "2147483647", "-2147483648"}
	for _, b := range boundaries {
		found := false
		for _, p := range payloads {
			if p == b {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected boundary value %s to be in payloads", b)
		}
	}
}

func TestEncodingEngine(t *testing.T) {
	ee := generator.NewEncodingEngine()

	tests := []struct {
		name     string
		payload  string
		method   string
		expected string
	}{
		{"URL encode", "test value", "url", "test+value"},
		{"Base64 encode", "test", "base64", "dGVzdA=="},
		{"Hex encode", "AB", "hex", "4142"},
		{"JSON wrap", "123", "json_wrap", `{"id":"123"}`},
		{"Array wrap", "123", "array", `["123"]`},
		{"No encoding", "test", "none", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ee.Encode(tt.payload, tt.method)
			if result != tt.expected {
				t.Errorf("Encode(%s, %s) = %s, want %s", tt.payload, tt.method, result, tt.expected)
			}
		})
	}
}

func TestUnicodeEncode(t *testing.T) {
	ee := generator.NewEncodingEngine()

	result := ee.Encode("AB", "unicode")
	expected := "\\u0041\\u0042"

	if result != expected {
		t.Errorf("Unicode encode failed: got %s, want %s", result, expected)
	}
}
