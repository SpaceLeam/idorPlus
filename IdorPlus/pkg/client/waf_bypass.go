package client

import (
	"math/rand"
	"net/http"
)

type WAFBypass struct {
	Enabled    bool
	Mode       string
	Headers    map[string]string
	UserAgents []string
}

func NewWAFBypass(enabled bool, mode string, headers map[string]string) *WAFBypass {
	return &WAFBypass{
		Enabled: enabled,
		Mode:    mode,
		Headers: headers,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		},
	}
}

func (w *WAFBypass) Apply(req *http.Request) {
	if !w.Enabled {
		return
	}

	// 1. Inject Bypass Headers
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}

	// 2. Rotate User-Agent (Go 1.20+ auto-seeds)
	ua := w.UserAgents[rand.Intn(len(w.UserAgents))]
	req.Header.Set("User-Agent", ua)

	// 3. Mode specific logic
	if w.Mode == "aggressive" {
		req.Header.Set("X-Originating-IP", "127.0.0.1")
		req.Header.Set("X-Remote-IP", "127.0.0.1")
		req.Header.Set("X-Client-IP", "127.0.0.1")
	}
}
