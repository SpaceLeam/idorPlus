package cmd

import (
	"fmt"
	"os"

	"idorplus/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	cfgFile string
	version = "2.0.0"
)

var rootCmd = &cobra.Command{
	Use:   "idorplus",
	Short: "Advanced IDOR Hunter",
	Long:  `IdorPlus - Ultimate IDOR vulnerability scanner with WAF bypass and smart fuzzing.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		utils.PrintBanner(version)
		utils.InitLogger(true) // Enable debug by default for now
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./configs/default.yaml)")
}
