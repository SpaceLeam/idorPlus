package generator

import (
	"time"

	"github.com/google/uuid"
)

type UUIDGenerator struct{}

func NewUUIDGenerator() *UUIDGenerator {
	return &UUIDGenerator{}
}

func (ug *UUIDGenerator) Generate(count int) []string {
	payloads := []string{}

	// UUID v1 (time-based - predictable!)
	for i := 0; i < count/2; i++ {
		u, _ := uuid.NewUUID() // v1
		payloads = append(payloads, u.String())
		// Small delay to vary the time component
		time.Sleep(10 * time.Microsecond)
	}

	// UUID v4 (random)
	for i := 0; i < count/2; i++ {
		u := uuid.New() // v4
		payloads = append(payloads, u.String())
	}

	return payloads
}
