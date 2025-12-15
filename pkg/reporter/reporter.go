package reporter

import (
	"encoding/json"
	"os"
	"time"

	"idorplus/pkg/fuzzer"
)

type Reporter struct {
	Findings []*fuzzer.FuzzResult
	Format   string
}

type Report struct {
	ScanTime time.Time            `json:"scan_time"`
	Findings []*fuzzer.FuzzResult `json:"findings"`
}

func NewReporter(format string) *Reporter {
	return &Reporter{
		Format: format,
	}
}

func (r *Reporter) AddFinding(f *fuzzer.FuzzResult) {
	r.Findings = append(r.Findings, f)
}

func (r *Reporter) GenerateReport(filename string) error {
	report := Report{
		ScanTime: time.Now(),
		Findings: r.Findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
