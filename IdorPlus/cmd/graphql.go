package cmd

import (
	"fmt"

	"idorplus/pkg/client"
	"idorplus/pkg/graphql"
	"idorplus/pkg/utils"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var graphqlCmd = &cobra.Command{
	Use:   "graphql",
	Short: "Test GraphQL endpoints for IDOR",
	Long: `Test GraphQL endpoints for IDOR vulnerabilities.

Features:
  - Schema introspection to find ID-based queries
  - Batch query testing (aliasing attacks)
  - Mutation testing for privilege escalation

Example:
  idorplus graphql -u "https://api.target.com/graphql" -c "session=token"`,
	Run: runGraphQL,
}

func init() {
	rootCmd.AddCommand(graphqlCmd)

	graphqlCmd.Flags().StringP("url", "u", "", "GraphQL endpoint URL (required)")
	graphqlCmd.Flags().StringP("cookies", "c", "", "Session cookies")
	graphqlCmd.Flags().StringP("query", "q", "", "Specific query to test")
	graphqlCmd.Flags().StringP("id-field", "i", "id", "ID field name in query")
	graphqlCmd.Flags().StringP("valid-id", "V", "", "Known valid ID")
	graphqlCmd.Flags().StringP("invalid-id", "I", "", "ID to test access for")
	graphqlCmd.Flags().Bool("introspect", false, "Run introspection first")
	graphqlCmd.Flags().Bool("batch", false, "Test batch/aliasing attack")

	graphqlCmd.MarkFlagRequired("url")
}

func runGraphQL(cmd *cobra.Command, args []string) {
	url, _ := cmd.Flags().GetString("url")
	cookies, _ := cmd.Flags().GetString("cookies")
	query, _ := cmd.Flags().GetString("query")
	idField, _ := cmd.Flags().GetString("id-field")
	validID, _ := cmd.Flags().GetString("valid-id")
	invalidID, _ := cmd.Flags().GetString("invalid-id")
	introspect, _ := cmd.Flags().GetBool("introspect")
	batch, _ := cmd.Flags().GetBool("batch")

	utils.Info.Printf("GraphQL Endpoint: %s\n", url)

	// Initialize client
	cfg, _ := utils.LoadConfig("configs/default.yaml")
	if cfg == nil {
		cfg = getDefaultConfig()
	}

	c := client.NewSmartClient(cfg)
	if cookies != "" {
		c.GetSessionManager().AddSession("attacker", cookies)
	}

	// Create GraphQL tester
	gt := graphql.NewGraphQLTester(c, url)

	// Run introspection if requested
	if introspect {
		utils.PrintSection("Running Introspection")

		spinner, _ := pterm.DefaultSpinner.Start("Fetching schema...")
		result, err := gt.Introspect()
		if err != nil {
			spinner.Fail("Introspection failed: " + err.Error())
			return
		}
		spinner.Success("Introspection complete")

		// Show found queries with ID params
		if len(result.Queries) > 0 {
			pterm.Info.Printf("Found %d queries with ID parameters:\n", len(result.Queries))
			for _, q := range result.Queries {
				pterm.Printf("  - %s\n", q.Name)
			}
		} else {
			pterm.Warning.Println("No queries with ID parameters found")
		}
	}

	// Test specific query
	if query != "" && validID != "" && invalidID != "" {
		utils.PrintSection("Testing IDOR on Query: " + query)

		result, err := gt.TestIDOROnQuery(query, idField, validID, invalidID)
		if err != nil {
			utils.Error.Printf("Test failed: %v\n", err)
			return
		}

		// Show results
		tableData := pterm.TableData{
			{"Test", "Result"},
			{"Query", query},
			{"Valid ID Status", fmt.Sprintf("%d", result.ValidStatus)},
			{"Invalid ID Status", fmt.Sprintf("%d", result.InvalidStatus)},
			{"Vulnerable", fmt.Sprintf("%v", result.IsVulnerable)},
		}
		pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()

		if result.IsVulnerable {
			pterm.Error.Println("⚠️  IDOR VULNERABILITY DETECTED!")
			pterm.Printf("Evidence: %s\n", result.Evidence)
		} else {
			pterm.Success.Println("No IDOR detected")
		}
	}

	// Test batch attack
	if batch && query != "" {
		utils.PrintSection("Testing Batch/Aliasing Attack")

		testIDs := []string{"1", "2", "3", "4", "5", "10", "100"}
		if validID != "" {
			testIDs = append(testIDs, validID)
		}
		if invalidID != "" {
			testIDs = append(testIDs, invalidID)
		}

		vulnerableIDs, err := gt.TestBatchIDOR(query, idField, testIDs)
		if err != nil {
			utils.Error.Printf("Batch test failed: %v\n", err)
			return
		}

		if len(vulnerableIDs) > 0 {
			pterm.Error.Printf("⚠️  Accessible IDs found: %v\n", vulnerableIDs)
		} else {
			pterm.Success.Println("No additional accessible IDs found")
		}
	}
}
