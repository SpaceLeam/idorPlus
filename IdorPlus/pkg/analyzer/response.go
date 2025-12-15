package analyzer

import (
	"math"

	"github.com/go-resty/resty/v2"
	"github.com/lithammer/fuzzysearch/fuzzy"
)

type ResponseComparator struct {
	Baseline *resty.Response
}

type ComparisonResult struct {
	StatusMatch    bool
	LengthDiff     int
	BodySimilarity float64
}

func NewResponseComparator(baseline *resty.Response) *ResponseComparator {
	return &ResponseComparator{
		Baseline: baseline,
	}
}

func (rc *ResponseComparator) Compare(resp *resty.Response) *ComparisonResult {
	result := &ComparisonResult{}

	// Status code
	result.StatusMatch = (rc.Baseline.StatusCode() == resp.StatusCode())

	// Content length
	baselineLen := len(rc.Baseline.Body())
	respLen := len(resp.Body())
	result.LengthDiff = int(math.Abs(float64(baselineLen - respLen)))

	// Body similarity (Levenshtein based)
	// Note: For large bodies, Levenshtein is expensive.
	// We use a simplified approach or just length/status for now for performance,
	// but here is a placeholder for similarity if needed.
	// Using fuzzy.RankMatch or similar could be better.
	// For now, let's just use a simple ratio of length difference as a proxy for similarity
	// to avoid massive CPU usage on large bodies.

	if baselineLen > 0 {
		result.BodySimilarity = 1.0 - (float64(result.LengthDiff) / float64(baselineLen))
	} else {
		if respLen == 0 {
			result.BodySimilarity = 1.0
		} else {
			result.BodySimilarity = 0.0
		}
	}

	return result
}

// CalculateSimilarity is a helper if we want to do deep inspection later
func CalculateSimilarity(s1, s2 string) float64 {
	dist := fuzzy.LevenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - (float64(dist) / maxLen)
}
