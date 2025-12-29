package detector

import (
	"context"
	"sort"
	"strings"
	"time"

	"idorplus/pkg/client"
)

// BlindIDORDetector detects blind IDOR via timing analysis
type BlindIDORDetector struct {
	client    *client.SmartClient
	samples   int
	threshold float64
}

// TimingResult represents timing analysis result
type TimingResult struct {
	URL         string
	ValidTime   time.Duration
	InvalidTime time.Duration
	Difference  time.Duration
	IsAnomaly   bool
	Confidence  float64
}

// NewBlindIDORDetector creates a new blind IDOR detector
func NewBlindIDORDetector(c *client.SmartClient) *BlindIDORDetector {
	return &BlindIDORDetector{
		client:    c,
		samples:   5,
		threshold: 1.5,
	}
}

// DetectByTiming uses timing analysis to detect blind IDOR
func (b *BlindIDORDetector) DetectByTiming(ctx context.Context, validURL, invalidURL string) (*TimingResult, error) {
	validTimes := make([]time.Duration, b.samples)
	for i := 0; i < b.samples; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := time.Now()
		_, err := b.client.Request().Get(validURL)
		if err != nil {
			continue
		}
		validTimes[i] = time.Since(start)
		time.Sleep(100 * time.Millisecond)
	}

	invalidTimes := make([]time.Duration, b.samples)
	for i := 0; i < b.samples; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		start := time.Now()
		_, err := b.client.Request().Get(invalidURL)
		if err != nil {
			continue
		}
		invalidTimes[i] = time.Since(start)
		time.Sleep(100 * time.Millisecond)
	}

	validMedian := medianDuration(validTimes)
	invalidMedian := medianDuration(invalidTimes)

	var diff time.Duration
	if validMedian > invalidMedian {
		diff = validMedian - invalidMedian
	} else {
		diff = invalidMedian - validMedian
	}

	result := &TimingResult{
		URL:         validURL,
		ValidTime:   validMedian,
		InvalidTime: invalidMedian,
		Difference:  diff,
	}

	if validMedian > 0 && invalidMedian > 0 {
		ratio := float64(validMedian) / float64(invalidMedian)
		if ratio > b.threshold || ratio < (1/b.threshold) {
			result.IsAnomaly = true
			result.Confidence = calculateTimingConfidence(ratio, b.threshold)
		}
	}

	return result, nil
}

// DetectBySequence checks if IDs are sequential/predictable
func (b *BlindIDORDetector) DetectBySequence(ctx context.Context, baseURL string, ids []string) []string {
	var accessibleIDs []string

	for _, id := range ids {
		select {
		case <-ctx.Done():
			return accessibleIDs
		default:
		}

		resp, err := b.client.Request().Get(baseURL + id)
		if err != nil {
			continue
		}

		if resp.StatusCode() >= 200 && resp.StatusCode() < 300 {
			accessibleIDs = append(accessibleIDs, id)
		}

		time.Sleep(100 * time.Millisecond)
	}

	return accessibleIDs
}

// DetectByErrorMessage analyzes error messages for information disclosure
func (b *BlindIDORDetector) DetectByErrorMessage(ctx context.Context, url string, ids []string) map[string]string {
	errorPatterns := make(map[string]string)

	for _, id := range ids {
		select {
		case <-ctx.Done():
			return errorPatterns
		default:
		}

		resp, err := b.client.Request().Get(url + id)
		if err != nil {
			continue
		}

		body := string(resp.Body())

		if containsInfoLeakPattern(body) {
			errorPatterns[id] = extractErrorTypeBlind(body)
		}

		time.Sleep(100 * time.Millisecond)
	}

	return errorPatterns
}

func medianDuration(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	sorted := make([]time.Duration, len(times))
	copy(sorted, times)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i] < sorted[j]
	})

	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

func calculateTimingConfidence(ratio, threshold float64) float64 {
	diff := ratio
	if ratio < 1 {
		diff = 1 / ratio
	}

	confidence := (diff - 1) / (threshold - 1) * 100
	if confidence > 100 {
		confidence = 100
	}
	return confidence
}

func containsInfoLeakPattern(body string) bool {
	patterns := []string{
		"user not found",
		"resource exists",
		"permission denied",
		"access denied",
		"belongs to another",
		"not your",
		"unauthorized",
	}

	bodyLower := strings.ToLower(body)
	for _, p := range patterns {
		if strings.Contains(bodyLower, p) {
			return true
		}
	}
	return false
}

func extractErrorTypeBlind(body string) string {
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "not found") {
		return "NOT_FOUND"
	}
	if strings.Contains(bodyLower, "denied") {
		return "ACCESS_DENIED"
	}
	if strings.Contains(bodyLower, "unauthorized") {
		return "UNAUTHORIZED"
	}
	return "UNKNOWN"
}
