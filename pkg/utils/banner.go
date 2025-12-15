package utils

import "github.com/pterm/pterm"

// PrintBanner prints the IdorPlus banner
func PrintBanner(version string) {
	banner := pterm.DefaultBigText.WithLetters(
		pterm.NewLettersFromStringWithStyle("IDOR", pterm.NewStyle(pterm.FgLightCyan)),
		pterm.NewLettersFromStringWithStyle("PLUS", pterm.NewStyle(pterm.FgLightMagenta)),
	)
	banner.Render()

	pterm.DefaultCenter.Printf("v%s - Advanced IDOR Vulnerability Hunter\n", version)
	pterm.DefaultCenter.Println(pterm.LightYellow("WAF Bypass | Smart Fuzzing | Auth Matrix Testing"))
	pterm.Println()
}

// PrintCompactBanner prints a compact banner for CI/CD
func PrintCompactBanner(version string) {
	pterm.DefaultHeader.
		WithBackgroundStyle(pterm.NewStyle(pterm.BgDarkGray)).
		WithTextStyle(pterm.NewStyle(pterm.FgLightCyan, pterm.Bold)).
		Printf(" IdorPlus v%s ", version)
	pterm.Println()
}

// PrintSection prints a section header
func PrintSection(title string) {
	pterm.DefaultSection.Println(title)
}

// PrintSuccess prints a success message
func PrintSuccess(msg string) {
	pterm.Success.Println(msg)
}

// PrintError prints an error message
func PrintError(msg string) {
	pterm.Error.Println(msg)
}

// PrintWarning prints a warning message
func PrintWarning(msg string) {
	pterm.Warning.Println(msg)
}

// PrintInfo prints an info message
func PrintInfo(msg string) {
	pterm.Info.Println(msg)
}

// PrintVulnerable prints a vulnerability found message
func PrintVulnerable(url string, status int) {
	pterm.NewStyle(pterm.FgRed, pterm.Bold).Printf("[VULN] ")
	pterm.Printf("%s (Status: %d)\n", url, status)
}
