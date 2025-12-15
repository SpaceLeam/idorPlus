package detector

import (
	"idorplus/pkg/analyzer"

	"github.com/go-resty/resty/v2"
)

type IDORDetector struct {
	Comparator *analyzer.ResponseComparator
	Threshold  float64
}

func NewIDORDetector(comparator *analyzer.ResponseComparator, threshold float64) *IDORDetector {
	return &IDORDetector{
		Comparator: comparator,
		Threshold:  threshold,
	}
}

func (id *IDORDetector) Detect(test *resty.Response) bool {
	comparison := id.Comparator.Compare(test)

	// IDOR indicators:
	// 1. Status 200 (should be 403/404)
	// 2. Content length significantly different
	// 3. Contains sensitive data patterns (TODO)

	// If baseline was 403/401 and test is 200 -> Vulnerable
	if (id.Comparator.Baseline.StatusCode() == 403 || id.Comparator.Baseline.StatusCode() == 401) && test.StatusCode() == 200 {
		return true
	}

	// If baseline was 200 (Attacker's own resource) and test is 200
	// We check for similarity. If it's too different, it might be another user's data.
	// OR if it's too similar, it might be a generic error page (Soft 404).

	// For now, let's assume a simple logic:
	// If status is 200 and body is NOT identical to baseline (assuming baseline is an error or empty), it's interesting.
	// But wait, baseline usually is "Attacker accessing their OWN resource" (Success) OR "Attacker accessing INVALID resource" (Error).
	// Let's assume the baseline passed to this detector is the "Error/Forbidden" response for an invalid ID.

	if test.StatusCode() >= 200 && test.StatusCode() < 300 {
		// If the response is very different from the error baseline
		if comparison.BodySimilarity < id.Threshold {
			return true
		}
	}

	return false
}
