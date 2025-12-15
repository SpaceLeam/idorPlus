package cmd

import (
	"fmt"

	"idorplus/pkg/client"
	"idorplus/pkg/crawler"
	"idorplus/pkg/utils"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var crawlCmd = &cobra.Command{
	Use:   "crawl",
	Short: "Crawl target to discover endpoints",
	Long: `Crawl a target website to discover API endpoints and parameters.

The crawler will:
  1. Spider the target recursively
  2. Extract API endpoints from HTML and JavaScript
  3. Identify potential IDOR parameters
  4. Output discovered endpoints for scanning`,
	Run: runCrawl,
}

func init() {
	rootCmd.AddCommand(crawlCmd)

	crawlCmd.Flags().StringP("url", "u", "", "Target URL to crawl (required)")
	crawlCmd.Flags().StringP("cookies", "c", "", "Session cookies")
	crawlCmd.Flags().IntP("depth", "d", 2, "Crawl depth")
	crawlCmd.Flags().IntP("max-pages", "m", 100, "Maximum pages to crawl")
	crawlCmd.Flags().StringP("output", "o", "endpoints.txt", "Output file for discovered endpoints")
	crawlCmd.Flags().Bool("js", true, "Parse JavaScript files for endpoints")

	crawlCmd.MarkFlagRequired("url")
}

func runCrawl(cmd *cobra.Command, args []string) {
	url, _ := cmd.Flags().GetString("url")
	cookies, _ := cmd.Flags().GetString("cookies")
	depth, _ := cmd.Flags().GetInt("depth")
	maxPages, _ := cmd.Flags().GetInt("max-pages")
	output, _ := cmd.Flags().GetString("output")

	utils.Info.Printf("Target: %s\n", url)
	utils.Info.Printf("Depth: %d | Max Pages: %d\n", depth, maxPages)

	// Load config
	cfg, _ := utils.LoadConfig("configs/default.yaml")
	if cfg == nil {
		cfg = getDefaultConfig()
	}

	// Initialize client
	c := client.NewSmartClient(cfg)
	if cookies != "" {
		c.GetSessionManager().AddSession("crawler", cookies)
	}

	// Initialize crawler
	cr := crawler.NewCrawler(c)
	cr.Depth = depth
	cr.MaxPages = maxPages

	// Start crawling with spinner
	spinner, _ := pterm.DefaultSpinner.Start("Crawling target...")

	endpoints := cr.Crawl(url)

	spinner.Success(fmt.Sprintf("Found %d endpoints", len(endpoints)))

	// Display results
	if len(endpoints) > 0 {
		pterm.DefaultSection.Println("Discovered Endpoints")

		// Show first 20
		displayCount := len(endpoints)
		if displayCount > 20 {
			displayCount = 20
		}

		for i := 0; i < displayCount; i++ {
			pterm.Printf("  %s\n", endpoints[i])
		}

		if len(endpoints) > 20 {
			pterm.Printf("  ... and %d more\n", len(endpoints)-20)
		}

		// Save to file
		if err := saveEndpoints(endpoints, output); err != nil {
			utils.Error.Printf("Failed to save endpoints: %v\n", err)
		} else {
			utils.Success.Printf("Saved %d endpoints to %s\n", len(endpoints), output)
		}
	} else {
		utils.Warning.Println("No endpoints discovered")
	}
}

func saveEndpoints(endpoints []string, path string) error {
	content := ""
	for _, ep := range endpoints {
		content += ep + "\n"
	}
	return utils.WriteFile(path, []byte(content))
}
