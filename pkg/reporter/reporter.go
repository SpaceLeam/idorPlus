package reporter

import (
	"encoding/json"
	"fmt"
	"time"

	"idorplus/pkg/fuzzer"
	"idorplus/pkg/utils"

	"github.com/pterm/pterm"
)

// Reporter generates scan reports in multiple formats
type Reporter struct {
	Findings  []*Finding
	Format    string
	StartTime time.Time
}

// Finding represents a discovered vulnerability
type Finding struct {
	URL         string              `json:"url"`
	Method      string              `json:"method"`
	Payload     string              `json:"payload"`
	StatusCode  int                 `json:"status_code"`
	ContentLen  int                 `json:"content_length"`
	Evidence    string              `json:"evidence,omitempty"`
	PIIFound    map[string][]string `json:"pii_found,omitempty"`
	Severity    string              `json:"severity"`
	Timestamp   time.Time           `json:"timestamp"`
	RequestTime time.Duration       `json:"request_time"`
}

// Report is the complete scan report
type Report struct {
	ScanTime   time.Time  `json:"scan_time"`
	Duration   string     `json:"duration"`
	TargetURL  string     `json:"target_url,omitempty"`
	TotalScans int        `json:"total_scans"`
	VulnCount  int        `json:"vulnerabilities_found"`
	Findings   []*Finding `json:"findings"`
}

// NewReporter creates a new reporter
func NewReporter(format string) *Reporter {
	return &Reporter{
		Format:    format,
		StartTime: time.Now(),
		Findings:  make([]*Finding, 0),
	}
}

// AddFinding adds a finding from a fuzz result
func (r *Reporter) AddFinding(result *fuzzer.FuzzResult) {
	finding := &Finding{
		URL:         result.Job.URL,
		Method:      result.Job.Method,
		Payload:     result.Job.Payload,
		StatusCode:  result.StatusCode,
		ContentLen:  result.ContentLen,
		Severity:    determineSeverity(result),
		Timestamp:   time.Now(),
		RequestTime: result.Duration,
	}

	// Truncate evidence to prevent huge reports
	if len(result.Evidence) > 1000 {
		finding.Evidence = result.Evidence[:1000] + "...[truncated]"
	} else {
		finding.Evidence = result.Evidence
	}

	r.Findings = append(r.Findings, finding)
}

// GenerateReport generates the report to file
func (r *Reporter) GenerateReport(filename string) error {
	report := &Report{
		ScanTime:   r.StartTime,
		Duration:   time.Since(r.StartTime).Round(time.Second).String(),
		TotalScans: len(r.Findings),
		VulnCount:  len(r.Findings),
		Findings:   r.Findings,
	}

	switch r.Format {
	case "json":
		return r.generateJSON(filename, report)
	case "markdown":
		return r.generateMarkdown(filename, report)
	default:
		return r.generateJSON(filename, report)
	}
}

// generateJSON outputs JSON format
func (r *Reporter) generateJSON(filename string, report *Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return utils.WriteFile(filename, data)
}

// generateMarkdown outputs Markdown format
func (r *Reporter) generateMarkdown(filename string, report *Report) error {
	content := "# IDOR Scan Report\n\n"
	content += fmt.Sprintf("**Scan Time:** %s\n", report.ScanTime.Format(time.RFC3339))
	content += fmt.Sprintf("**Duration:** %s\n", report.Duration)
	content += fmt.Sprintf("**Vulnerabilities Found:** %d\n\n", report.VulnCount)

	content += "## Findings\n\n"

	for i, f := range report.Findings {
		content += fmt.Sprintf("### %d. %s\n\n", i+1, f.URL)
		content += fmt.Sprintf("- **Method:** %s\n", f.Method)
		content += fmt.Sprintf("- **Payload:** `%s`\n", f.Payload)
		content += fmt.Sprintf("- **Status Code:** %d\n", f.StatusCode)
		content += fmt.Sprintf("- **Severity:** %s\n", f.Severity)
		content += fmt.Sprintf("- **Content Length:** %d bytes\n\n", f.ContentLen)

		if f.Evidence != "" {
			content += "**Evidence:**\n```\n" + f.Evidence + "\n```\n\n"
		}
	}

	return utils.WriteFile(filename, []byte(content))
}

// PrintSummary prints a summary of findings to console
func (r *Reporter) PrintSummary() {
	pterm.DefaultSection.Println("Scan Summary")

	if len(r.Findings) == 0 {
		pterm.Success.Println("No vulnerabilities found")
		return
	}

	tableData := pterm.TableData{
		{"URL", "Method", "Status", "Severity"},
	}

	for _, f := range r.Findings {
		severity := f.Severity
		switch severity {
		case "CRITICAL":
			severity = pterm.Red(severity)
		case "HIGH":
			severity = pterm.LightRed(severity)
		case "MEDIUM":
			severity = pterm.Yellow(severity)
		default:
			severity = pterm.Green(severity)
		}

		tableData = append(tableData, []string{
			truncate(f.URL, 50),
			f.Method,
			fmt.Sprintf("%d", f.StatusCode),
			severity,
		})
	}

	pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}

// determineSeverity determines severity based on finding characteristics
func determineSeverity(result *fuzzer.FuzzResult) string {
	// High severity if status code changed from expected error to success
	if result.StatusCode == 200 {
		return "HIGH"
	}

	// Medium if there's content but not 200
	if result.ContentLen > 100 {
		return "MEDIUM"
	}

	return "LOW"
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
