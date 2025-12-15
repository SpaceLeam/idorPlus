package generator

import "fmt"

type NumericGenerator struct{}

func NewNumericGenerator() *NumericGenerator {
	return &NumericGenerator{}
}

func (ng *NumericGenerator) Generate(count int) []string {
	payloads := []string{}

	// Sequential
	for i := 1; i <= count; i++ {
		payloads = append(payloads, fmt.Sprintf("%d", i))
	}

	// Boundary values
	boundaries := []string{
		"0", "1", "-1",
		"999", "1000", "1001",
		"9999", "10000",
		"2147483647",  // Max int32
		"-2147483648", // Min int32
	}
	payloads = append(payloads, boundaries...)

	return payloads
}
