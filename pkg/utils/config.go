package utils

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure
type Config struct {
	Scanner   ScannerConfig   `yaml:"scanner"`
	WAFBypass WAFBypassConfig `yaml:"waf_bypass"`
	Detection DetectionConfig `yaml:"detection"`
	Output    OutputConfig    `yaml:"output"`
}

type ScannerConfig struct {
	Threads    int    `yaml:"threads"`
	Timeout    string `yaml:"timeout"`
	MaxRetries int    `yaml:"max_retries"`
	Delay      string `yaml:"delay"`
	VerifyTLS  bool   `yaml:"verify_tls"`
}

type WAFBypassConfig struct {
	Enabled bool              `yaml:"enabled"`
	Mode    string            `yaml:"mode"`
	Headers map[string]string `yaml:"headers"`
}

type DetectionConfig struct {
	Threshold float64 `yaml:"threshold"`
	CheckPII  bool    `yaml:"check_pii"`
	BlindIDOR bool    `yaml:"blind_idor"`
}

type OutputConfig struct {
	Format        string `yaml:"format"`
	Verbose       bool   `yaml:"verbose"`
	SaveResponses bool   `yaml:"save_responses"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
