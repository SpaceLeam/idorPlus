package cmd

import (
	"strings"

	"idorplus/pkg/analyzer"
	"idorplus/pkg/client"
	"idorplus/pkg/detector"
	"idorplus/pkg/fuzzer"
	"idorplus/pkg/generator"
	"idorplus/pkg/reporter"
	"idorplus/pkg/utils"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Start IDOR scanning",
	Run: func(cmd *cobra.Command, args []string) {
		url, _ := cmd.Flags().GetString("url")
		cookies, _ := cmd.Flags().GetString("cookies")
		threads, _ := cmd.Flags().GetInt("threads")
		bypass, _ := cmd.Flags().GetString("bypass")

		utils.Info.Println("Starting scan on:", url)

		// Load Config
		cfg, _ := utils.LoadConfig("configs/default.yaml")
		if cfg == nil {
			cfg = &utils.Config{} // Fallback
		}

		// Override config with flags
		cfg.Scanner.Threads = threads
		cfg.WAFBypass.Mode = bypass
		if bypass != "none" {
			cfg.WAFBypass.Enabled = true
		}

		// Init Client
		c := client.NewSmartClient(cfg)
		c.GetSessionManager().AddSession("attacker", cookies)

		// Baseline Request (to get 403/404 or normal response)
		// We assume the URL provided HAS the ID we want to fuzz.
		// e.g. http://target.com/user/123
		// We need to identify WHERE the ID is.
		// For this MVP, let's assume the user puts a placeholder {ID} or we just fuzz the last path segment if numeric.

		targetURL := url
		if !strings.Contains(url, "{ID}") {
			utils.Warning.Println("No {ID} placeholder found. Appending payloads to end of URL.")
		}

		// Analyzer & Generator
		// For now, let's assume Numeric ID type for simplicity or auto-detect from the URL if possible.
		// Real implementation would analyze the existing ID in the URL.
		gen := generator.NewPayloadGenerator(analyzer.TypeNumeric)
		payloads := gen.Generate(100) // Generate 100 payloads

		// Init Detector
		// We need a baseline. Let's make a request to a non-existent ID to get a baseline error.
		baselineURL := strings.Replace(targetURL, "{ID}", "999999999", 1)
		baselineResp, err := c.Request().Get(baselineURL)
		if err != nil {
			utils.Error.Println("Failed to get baseline:", err)
			return
		}

		comp := analyzer.NewResponseComparator(baselineResp)
		det := detector.NewIDORDetector(comp, 0.8)

		// Init Fuzzer
		fe := fuzzer.NewFuzzEngine(c, threads, det)
		fe.Start()

		// Feed Jobs
		go func() {
			for _, p := range payloads {
				u := strings.Replace(targetURL, "{ID}", p, 1)
				if !strings.Contains(targetURL, "{ID}") {
					u = targetURL + "/" + p // Simple append fallback
				}

				fe.Queue <- &fuzzer.FuzzJob{
					URL:     u,
					Method:  "GET",
					Payload: p,
				}
			}
			fe.Stop()
		}()

		// Collect Results
		rep := reporter.NewReporter("json")
		for res := range fe.Results {
			if res.IsVulnerable {
				utils.Success.Printf("VULNERABLE: %s (Status: %d)\n", res.Job.URL, res.Response.StatusCode())
				rep.AddFinding(res)
			} else {
				// utils.Info.Printf("Checked: %s (Status: %d)\n", res.Job.URL, res.Response.StatusCode())
			}
		}

		// Save Report
		rep.GenerateReport("idor_report.json")
		utils.Info.Println("Scan complete. Report saved to idor_report.json")
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringP("url", "u", "", "Target URL with {ID} placeholder")
	scanCmd.Flags().StringP("cookies", "c", "", "Session cookies")
	scanCmd.Flags().IntP("threads", "t", 10, "Number of threads")
	scanCmd.Flags().StringP("bypass", "b", "normal", "WAF bypass mode")
	scanCmd.MarkFlagRequired("url")
}
