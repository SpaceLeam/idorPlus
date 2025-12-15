package analyzer

import (
	"regexp"

	"github.com/google/uuid"
)

type IDType int

const (
	TypeUnknown IDType = iota
	TypeNumeric
	TypeUUID
	TypeMD5
	TypeSHA1
	TypeBase64
)

type IdentifierAnalyzer struct{}

func NewIdentifierAnalyzer() *IdentifierAnalyzer {
	return &IdentifierAnalyzer{}
}

func (ia *IdentifierAnalyzer) DetectType(id string) IDType {
	// Numeric check first (most common)
	if matched, _ := regexp.MatchString(`^\d+$`, id); matched {
		return TypeNumeric
	}

	// MD5 check (32 hex chars, case-insensitive) - before UUID to avoid false match
	if matched, _ := regexp.MatchString(`^[a-fA-F0-9]{32}$`, id); matched {
		// Additional check: UUIDs have dashes, MD5 does not
		if !regexp.MustCompile(`-`).MatchString(id) {
			return TypeMD5
		}
	}

	// SHA1 check (40 hex chars, case-insensitive)
	if matched, _ := regexp.MatchString(`^[a-fA-F0-9]{40}$`, id); matched {
		return TypeSHA1
	}

	// UUID check (must contain dashes in standard format)
	if _, err := uuid.Parse(id); err == nil {
		return TypeUUID
	}

	// Base64 check (Simple heuristic)
	if matched, _ := regexp.MatchString(`^[A-Za-z0-9+/]+={0,2}$`, id); matched {
		// Ensure it has some length to avoid false positives with short strings
		if len(id) > 4 {
			return TypeBase64
		}
	}

	return TypeUnknown
}
