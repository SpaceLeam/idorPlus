package cmd

import (
	"context"
	"fmt"
	"strings"

	"idorplus/pkg/client"
	"idorplus/pkg/crawler"
	"idorplus/pkg/utils"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover shadow/hidden API endpoints",
	Long: `Discover hidden API endpoints from JavaScript files and HTML.

This command crawls the target and extracts:
  - API endpoints from JS files (fetch, axios, XHR)
  - Hidden endpoints from HTML (forms, data attributes)
  - Internal/admin endpoints
  - Endpoints with ID parameters (IDOR candidates)

Example:
  idorplus discover -u "https://target.com" -d 3 --js-only`,
	Run: runDiscover,
}

func init() {
	rootCmd.AddCommand(discoverCmd)

	discoverCmd.Flags().StringP("url", "u", "", "Target URL to crawl (required)")
	discoverCmd.Flags().StringP("cookies", "c", "", "Session cookies")
	discoverCmd.Flags().IntP("depth", "D", 2, "Crawl depth")
	discoverCmd.Flags().StringP("output", "o", "discovered_apis.txt", "Output file")
	discoverCmd.Flags().Bool("js-only", false, "Only parse JavaScript files")
	discoverCmd.Flags().Bool("internal", false, "Show only internal/admin endpoints")
	discoverCmd.Flags().Bool("idor", false, "Show only endpoints with ID parameters")

	discoverCmd.MarkFlagRequired("url")
}

func runDiscover(cmd *cobra.Command, args []string) {
	url, _ := cmd.Flags().GetString("url")
	cookies, _ := cmd.Flags().GetString("cookies")
	depth, _ := cmd.Flags().GetInt("depth")
	output, _ := cmd.Flags().GetString("output")
	jsOnly, _ := cmd.Flags().GetBool("js-only")
	internalOnly, _ := cmd.Flags().GetBool("internal")
	idorOnly, _ := cmd.Flags().GetBool("idor")

	utils.Info.Printf("Target: %s\n", url)
	utils.Info.Printf("Depth: %d\n", depth)

	// Initialize
	cfg, _ := utils.LoadConfig("configs/default.yaml")
	if cfg == nil {
		cfg = getDefaultConfig()
	}

	c := client.NewSmartClient(cfg)
	if cookies != "" {
		c.GetSessionManager().AddSession("crawler", cookies)
	}

	// Create shadow API discoverer
	discoverer := crawler.NewShadowAPIDiscoverer()

	// Create crawler to fetch pages
	cr := crawler.NewCrawler(c)
	cr.Depth = depth
	cr.MaxPages = 50

	spinner, _ := pterm.DefaultSpinner.Start("Crawling target...")

	// Crawl and collect content
	pages := cr.Crawl(url)
	spinner.UpdateText(fmt.Sprintf("Processing %d pages...", len(pages)))

	// For each discovered page, fetch and parse
	ctx := context.Background()
	for _, pageURL := range pages {
		// Rate limit to avoid WAF triggers
		c.GetRateLimiter().Wait(ctx)

		resp, err := c.Request().Get(pageURL)
		if err != nil {
			continue
		}

		body := string(resp.Body())
		contentType := resp.Header().Get("Content-Type")

		// Parse based on content type
		if strings.Contains(contentType, "javascript") || strings.HasSuffix(pageURL, ".js") {
			discoverer.ExtractFromJS(body, pageURL)
		} else if strings.Contains(contentType, "html") && !jsOnly {
			discoverer.ExtractFromHTML(body, pageURL)
			// Also extract inline scripts
			discoverer.ExtractFromJS(body, pageURL)
		} else if strings.Contains(contentType, "json") && !jsOnly {
			discoverer.ExtractFromJSON(body, pageURL)
		}
	}

	spinner.Success("Discovery complete")

	// Get results based on filters
	var endpoints []crawler.EndpointInfo

	if internalOnly {
		endpoints = discoverer.GetInternalEndpoints()
	} else if idorOnly {
		endpoints = discoverer.GetEndpointsWithIDParams()
	} else {
		endpoints = discoverer.GetAllEndpoints()
	}

	// Display results
	utils.PrintSection("Discovered Endpoints")

	if len(endpoints) == 0 {
		pterm.Warning.Println("No endpoints discovered")
		return
	}

	// Group by type
	var internalEps, idorEps, otherEps []crawler.EndpointInfo
	for _, ep := range endpoints {
		if ep.IsInternal {
			internalEps = append(internalEps, ep)
		} else if len(ep.ParamNames) > 0 {
			idorEps = append(idorEps, ep)
		} else {
			otherEps = append(otherEps, ep)
		}
	}

	// Show internal endpoints first (high value)
	if len(internalEps) > 0 {
		pterm.DefaultSection.Printf("🔴 Internal/Admin Endpoints (%d)\n", len(internalEps))
		for _, ep := range internalEps {
			pterm.Printf("  [%s] %s\n", ep.Method, ep.URL)
		}
	}

	// Show IDOR candidates
	if len(idorEps) > 0 {
		pterm.DefaultSection.Printf("🟡 IDOR Candidates (%d)\n", len(idorEps))
		for _, ep := range idorEps {
			params := strings.Join(ep.ParamNames, ", ")
			pterm.Printf("  [%s] %s (params: %s)\n", ep.Method, ep.URL, params)
		}
	}

	// Show other endpoints
	if len(otherEps) > 0 && !internalOnly && !idorOnly {
		shown := len(otherEps)
		if shown > 20 {
			shown = 20
		}
		pterm.DefaultSection.Printf("🟢 Other Endpoints (%d, showing %d)\n", len(otherEps), shown)
		for i := 0; i < shown; i++ {
			pterm.Printf("  [%s] %s\n", otherEps[i].Method, otherEps[i].URL)
		}
		if len(otherEps) > 20 {
			pterm.Printf("  ... and %d more\n", len(otherEps)-20)
		}
	}

	// Save to file
	var outputContent strings.Builder
	outputContent.WriteString("# Discovered API Endpoints\n\n")

	if len(internalEps) > 0 {
		outputContent.WriteString("## Internal/Admin\n")
		for _, ep := range internalEps {
			outputContent.WriteString(fmt.Sprintf("%s %s\n", ep.Method, ep.URL))
		}
		outputContent.WriteString("\n")
	}

	if len(idorEps) > 0 {
		outputContent.WriteString("## IDOR Candidates\n")
		for _, ep := range idorEps {
			outputContent.WriteString(fmt.Sprintf("%s %s # params: %s\n", ep.Method, ep.URL, strings.Join(ep.ParamNames, ",")))
		}
		outputContent.WriteString("\n")
	}

	outputContent.WriteString("## Other\n")
	for _, ep := range otherEps {
		outputContent.WriteString(fmt.Sprintf("%s %s\n", ep.Method, ep.URL))
	}

	if err := utils.WriteFile(output, []byte(outputContent.String())); err != nil {
		utils.Error.Printf("Failed to save: %v\n", err)
	} else {
		utils.Success.Printf("Saved %d endpoints to %s\n", len(endpoints), output)
	}

	// Summary
	pterm.DefaultSection.Println("Summary")
	tableData := pterm.TableData{
		{"Category", "Count"},
		{"Internal/Admin", fmt.Sprintf("%d", len(internalEps))},
		{"IDOR Candidates", fmt.Sprintf("%d", len(idorEps))},
		{"Other", fmt.Sprintf("%d", len(otherEps))},
		{"Total", fmt.Sprintf("%d", len(endpoints))},
	}
	pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
}
