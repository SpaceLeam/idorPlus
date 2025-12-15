package cmd

import (
	"fmt"
	"os"

	"idorplus/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	cfgFile   string
	verbose   bool
	debug     bool
	version   = "2.0.0"
	proxyList []string
)

var rootCmd = &cobra.Command{
	Use:   "idorplus",
	Short: "Advanced IDOR Hunter",
	Long: `IdorPlus - Ultimate IDOR vulnerability scanner with WAF bypass and smart fuzzing.

Features:
  - WAF Bypass (Header spoofing, UA rotation, encoding tricks)
  - Rate Limiting with jitter
  - Proxy Rotation
  - Auth Matrix Testing
  - PII Detection
  - Smart Pattern Analysis`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Don't print banner for version or help
		if cmd.Name() == "version" || cmd.Name() == "help" {
			return
		}
		utils.PrintBanner(version)
		utils.InitLogger(debug)
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./configs/default.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "debug mode")
	rootCmd.PersistentFlags().StringSliceVar(&proxyList, "proxy", []string{}, "proxy list for rotation (can be specified multiple times)")
}
