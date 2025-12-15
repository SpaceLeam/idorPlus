package utils

import (
	"github.com/pterm/pterm"
)

var (
	// Logger instances
	Info    = pterm.Info
	Success = pterm.Success
	Warning = pterm.Warning
	Error   = pterm.Error
	Debug   = pterm.Debug
)

// InitLogger initializes the logger settings
func InitLogger(debugMode bool) {
	if debugMode {
		pterm.EnableDebugMessages()
	} else {
		pterm.DisableDebugMessages()
	}
}

// PrintBanner prints the tool banner
func PrintBanner(version string) {
	pterm.DefaultHeader.
		WithBackgroundStyle(pterm.NewStyle(pterm.BgLightBlue)).
		WithMargin(10).
		Printf("IdorPlus v%s - Advanced IDOR Hunter\n", version)
}
