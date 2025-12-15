package cmd

import (
	"fmt"
	"runtime"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		pterm.DefaultHeader.
			WithBackgroundStyle(pterm.NewStyle(pterm.BgDarkGray)).
			Printf(" IdorPlus v%s ", version)
		pterm.Println()

		tableData := pterm.TableData{
			{"Property", "Value"},
			{"Version", version},
			{"Go Version", runtime.Version()},
			{"OS/Arch", fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)},
			{"Compiler", runtime.Compiler},
		}

		pterm.DefaultTable.WithHasHeader().WithData(tableData).Render()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
