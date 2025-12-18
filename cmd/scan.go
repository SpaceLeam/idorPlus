package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"idorplus/pkg/analyzer"
	"idorplus/pkg/client"
	"idorplus/pkg/detector"
	"idorplus/pkg/fuzzer"
	"idorplus/pkg/generator"
	"idorplus/pkg/reporter"
	"idorplus/pkg/utils"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start IDOR scanning",
	Long: `Scan a target URL for IDOR vulnerabilities.

Use {ID} as a placeholder in the URL where you want to fuzz:
  idorplus scan -u "https://api.target.com/users/{ID}/profile" -c "session=token"

The scanner will:
  1. Establish baseline responses
  2. Generate payloads based on detected ID type
  3. Fuzz the ID parameter with WAF bypass techniques
  4. Detect vulnerable endpoints using multiple heuristics`,
	Run: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringP("url", "u", "", "Target URL with {ID} placeholder (required)")
	scanCmd.Flags().StringP("cookies", "c", "", "Session cookies")
	scanCmd.Flags().StringP("cookies-b", "C", "", "Second user cookies for auth matrix testing")
	scanCmd.Flags().IntP("threads", "t", 10, "Number of concurrent workers")
	scanCmd.Flags().StringP("wordlist", "w", "", "Custom wordlist file")
	scanCmd.Flags().IntP("count", "n", 100, "Number of payloads to generate (if no wordlist)")
	scanCmd.Flags().StringP("bypass", "b", "normal", "WAF bypass mode: none, normal, aggressive, stealth")
	scanCmd.Flags().StringP("method", "m", "GET", "HTTP method: GET, POST, PUT, DELETE, PATCH")
	scanCmd.Flags().StringP("output", "o", "idor_report.json", "Output report file")
	scanCmd.Flags().Float64P("threshold", "T", 0.8, "Similarity threshold for detection (0.0-1.0)")
	scanCmd.Flags().Bool("auth-matrix", false, "Enable auth matrix testing (requires -C)")
	scanCmd.Flags().Bool("pii", true, "Enable PII detection")
	scanCmd.Flags().Int("delay", 100, "Delay between requests in milliseconds")
	scanCmd.Flags().StringArrayP("header", "H", nil, "Custom headers (e.g. -H 'Authorization: Bearer token')")
	scanCmd.Flags().StringP("auth", "a", "", "Bearer token for Authorization header")
	scanCmd.Flags().BoolP("insecure", "k", false, "Skip SSL verification")

	scanCmd.MarkFlagRequired("url")
}

func runScan(cmd *cobra.Command, args []string) {
	// Parse flags
	url, _ := cmd.Flags().GetString("url")
	cookies, _ := cmd.Flags().GetString("cookies")
	cookiesB, _ := cmd.Flags().GetString("cookies-b")
	threads, _ := cmd.Flags().GetInt("threads")
	wordlistPath, _ := cmd.Flags().GetString("wordlist")
	count, _ := cmd.Flags().GetInt("count")
	bypass, _ := cmd.Flags().GetString("bypass")
	method, _ := cmd.Flags().GetString("method")
	outputFile, _ := cmd.Flags().GetString("output")
	threshold, _ := cmd.Flags().GetFloat64("threshold")
	authMatrix, _ := cmd.Flags().GetBool("auth-matrix")
	piiCheck, _ := cmd.Flags().GetBool("pii")
	delay, _ := cmd.Flags().GetInt("delay")
	customHeaders, _ := cmd.Flags().GetStringArray("header")
	bearerToken, _ := cmd.Flags().GetString("auth")
	skipSSL, _ := cmd.Flags().GetBool("insecure")

	utils.Info.Printf("Target: %s\n", url)
	utils.Info.Printf("Mode: %s | Threads: %d | Method: %s\n", bypass, threads, method)

	// Load config
	cfg, err := utils.LoadConfig("configs/default.yaml")
	if err != nil {
		utils.Warning.Printf("Config not found, using defaults\n")
		cfg = getDefaultConfig()
	}

	// Override config with flags
	cfg.Scanner.Threads = threads
	cfg.WAFBypass.Mode = bypass
	cfg.WAFBypass.Enabled = bypass != "none"
	cfg.Detection.Threshold = threshold
	cfg.Detection.CheckPII = piiCheck
	cfg.Scanner.Delay = fmt.Sprintf("%dms", delay)
	if skipSSL {
		cfg.Scanner.SkipSSL = true
	}

	// Initialize client
	c := client.NewSmartClient(cfg)

	// Set up sessions
	if cookies != "" {
		c.GetSessionManager().AddSession("attacker", cookies)
	}
	if cookiesB != "" {
		c.GetSessionManager().AddSession("victim", cookiesB)
	}

	// Set proxies if provided
	if len(proxyList) > 0 {
		c.SetProxies(proxyList)
		utils.Info.Printf("Using %d proxies\n", len(proxyList))
	}

	// Add custom headers
	for _, h := range customHeaders {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			c.SetDefaultHeader(key, val)
			utils.Info.Printf("Custom header: %s\n", key)
		}
	}

	// Add bearer token
	if bearerToken != "" {
		c.SetDefaultHeader("Authorization", "Bearer "+bearerToken)
		utils.Info.Println("Using Bearer token authentication")
	}

	// Generate or load payloads
	var payloads []string
	if wordlistPath != "" {
		payloads, err = utils.LoadWordlist(wordlistPath)
		if err != nil {
			utils.Error.Printf("Failed to load wordlist: %v\n", err)
			return
		}
		utils.Info.Printf("Loaded %d payloads from wordlist\n", len(payloads))
	} else {
		// Detect ID type from URL
		existingID := extractExistingID(url)
		idType := analyzer.TypeNumeric
		if existingID != "" {
			ia := analyzer.NewIdentifierAnalyzer()
			idType = ia.DetectType(existingID)
			utils.Info.Printf("Detected ID type: %v\n", idType)
		}

		gen := generator.NewPayloadGenerator(idType)
		payloads = gen.Generate(count)
		utils.Info.Printf("Generated %d payloads\n", len(payloads))
	}

	// Get baselines
	utils.Info.Println("Establishing baselines...")

	// Invalid baseline (non-existent resource)
	invalidURL := replaceID(url, "999999999999999")
	invalidResp, err := c.Request().Get(invalidURL)
	if err != nil {
		utils.Error.Printf("Failed to get invalid baseline: %v\n", err)
		return
	}
	utils.Debug.Printf("Invalid baseline: Status %d, Length %d\n", invalidResp.StatusCode(), len(invalidResp.Body()))

	// Valid baseline (if we have an existing ID in the URL)
	var validResp = invalidResp // Fallback
	existingID := extractExistingID(url)
	if existingID != "" && cookies != "" {
		validURL := replaceID(url, existingID)
		vr, err := c.Request().Get(validURL)
		if err == nil {
			validResp = vr
			utils.Debug.Printf("Valid baseline: Status %d, Length %d\n", validResp.StatusCode(), len(validResp.Body()))
		}
	}

	// Create detector
	det := detector.NewIDORDetector(validResp, invalidResp, threshold, piiCheck)

	// Auth Matrix testing
	if authMatrix && cookiesB != "" {
		utils.PrintSection("Auth Matrix Testing")
		amt := detector.NewAuthMatrixTester(c)
		amt.AddSession("user_a", cookies)
		amt.AddSession("user_b", cookiesB)

		testURL := replaceID(url, existingID)
		result := amt.TestEndpoint(testURL, method)
		amt.PrintMatrix(result)
	}

	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		utils.Warning.Println("\nInterrupt received, stopping scan...")
		cancel()
	}()

	// Initialize fuzzer
	fe := fuzzer.NewFuzzEngine(c, threads, det)
	fe.Start()

	// Setup progress bar
	progressBar, _ := pterm.DefaultProgressbar.
		WithTotal(len(payloads)).
		WithTitle("Scanning").
		WithShowElapsedTime(true).
		WithShowCount(true).
		Start()

	// Feed jobs in goroutine
	go func() {
	JobLoop:
		for i, p := range payloads {
			select {
			case <-ctx.Done():
				break JobLoop
			default:
				targetURL := replaceID(url, p)
				job := &fuzzer.FuzzJob{
					ID:      i,
					URL:     targetURL,
					Method:  method,
					Payload: p,
					Session: "attacker",
				}
				if !fe.Submit(job) {
					break JobLoop
				}
			}
		}
		fe.CloseQueue()
		fe.WaitAndClose() // Wait for workers and close Results channel
	}()

	// Collect results
	rep := reporter.NewReporter("json")
	done := make(chan bool)

	go func() {
		for result := range fe.Results {
			progressBar.Increment()

			if result.IsVulnerable {
				progressBar.UpdateTitle(pterm.Red("VULNERABLE FOUND!"))
				utils.PrintVulnerable(result.Job.URL, result.StatusCode)
				rep.AddFinding(result)
			}
		}
		done <- true
	}()

	// Wait for completion
	<-done
	progressBar.Stop()

	// Print stats
	fe.Stats.Print()

	// Save report
	if err := rep.GenerateReport(outputFile); err != nil {
		utils.Error.Printf("Failed to save report: %v\n", err)
	} else {
		utils.Success.Printf("Report saved to %s\n", outputFile)
	}

	// Summary
	if fe.Stats.GetVulnCount() > 0 {
		utils.Error.Printf("\n%d VULNERABILITIES FOUND!\n", fe.Stats.GetVulnCount())
	} else {
		utils.Success.Println("\nNo vulnerabilities found")
	}
}

func getDefaultConfig() *utils.Config {
	return &utils.Config{
		Scanner: utils.ScannerConfig{
			Threads:    10,
			Timeout:    "10s",
			MaxRetries: 3,
			Delay:      "100ms",
			SkipSSL:    false,
		},
		WAFBypass: utils.WAFBypassConfig{
			Enabled: true,
			Mode:    "normal",
			Headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
				"X-Real-IP":       "127.0.0.1",
			},
		},
		Detection: utils.DetectionConfig{
			Threshold: 0.8,
			CheckPII:  true,
			BlindIDOR: false,
		},
		Output: utils.OutputConfig{
			Format:  "json",
			Verbose: true,
		},
	}
}

func replaceID(url, id string) string {
	if strings.Contains(url, "{ID}") {
		return strings.Replace(url, "{ID}", id, 1)
	}
	// Fallback: append to URL
	if strings.HasSuffix(url, "/") {
		return url + id
	}
	return url + "/" + id
}

func extractExistingID(url string) string {
	// Try to find an existing ID in the URL
	if strings.Contains(url, "{ID}") {
		return ""
	}
	return utils.ExtractIDFromURL(url)
}
