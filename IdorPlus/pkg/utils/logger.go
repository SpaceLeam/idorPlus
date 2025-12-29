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
