package fuzzer

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
)

// Stats tracks scanning statistics in real-time
type Stats struct {
	TotalRequests   int64
	SuccessCount    int64
	FailedCount     int64
	VulnCount       int64
	StartTime       time.Time
	LastRequestTime time.Time
	mu              sync.RWMutex
}

// NewStats creates a new stats tracker
func NewStats() *Stats {
	return &Stats{
		StartTime:       time.Now(),
		LastRequestTime: time.Now(),
	}
}

// IncrementTotal increments total request count
func (s *Stats) IncrementTotal() {
	atomic.AddInt64(&s.TotalRequests, 1)
	s.mu.Lock()
	s.LastRequestTime = time.Now()
	s.mu.Unlock()
}

// IncrementSuccess increments successful request count
func (s *Stats) IncrementSuccess() {
	atomic.AddInt64(&s.SuccessCount, 1)
}

// IncrementFailed increments failed request count
func (s *Stats) IncrementFailed() {
	atomic.AddInt64(&s.FailedCount, 1)
}

// IncrementVuln increments vulnerability count
func (s *Stats) IncrementVuln() {
	atomic.AddInt64(&s.VulnCount, 1)
}

// GetRPS calculates requests per second
func (s *Stats) GetRPS() float64 {
	elapsed := time.Since(s.StartTime).Seconds()
	if elapsed == 0 {
		return 0
	}
	return float64(atomic.LoadInt64(&s.TotalRequests)) / elapsed
}

// GetElapsed returns elapsed time
func (s *Stats) GetElapsed() time.Duration {
	return time.Since(s.StartTime)
}

// GetTotal returns total requests
func (s *Stats) GetTotal() int64 {
	return atomic.LoadInt64(&s.TotalRequests)
}

// GetVulnCount returns vulnerability count
func (s *Stats) GetVulnCount() int64 {
	return atomic.LoadInt64(&s.VulnCount)
}

// GetSuccessCount returns success count
func (s *Stats) GetSuccessCount() int64 {
	return atomic.LoadInt64(&s.SuccessCount)
}

// GetFailedCount returns failed count
func (s *Stats) GetFailedCount() int64 {
	return atomic.LoadInt64(&s.FailedCount)
}

// Print displays stats in a formatted table
func (s *Stats) Print() {
	total := atomic.LoadInt64(&s.TotalRequests)
	success := atomic.LoadInt64(&s.SuccessCount)
	failed := atomic.LoadInt64(&s.FailedCount)
	vulns := atomic.LoadInt64(&s.VulnCount)

	pterm.DefaultSection.Println("Scan Statistics")

	tableData := pterm.TableData{
		{"Metric", "Value"},
		{"Total Requests", fmt.Sprintf("%d", total)},
		{"Successful", fmt.Sprintf("%d", success)},
		{"Failed", fmt.Sprintf("%d", failed)},
		{"Vulnerabilities", pterm.LightRed(fmt.Sprintf("%d", vulns))},
		{"RPS", fmt.Sprintf("%.2f", s.GetRPS())},
		{"Elapsed", s.GetElapsed().Round(time.Second).String()},
	}

	pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}

// PrintSummary prints a compact summary
func (s *Stats) PrintSummary() string {
	total := atomic.LoadInt64(&s.TotalRequests)
	vulns := atomic.LoadInt64(&s.VulnCount)
	return fmt.Sprintf("Requests: %d | Vulns: %d | RPS: %.1f | Time: %s",
		total, vulns, s.GetRPS(), s.GetElapsed().Round(time.Second))
}
