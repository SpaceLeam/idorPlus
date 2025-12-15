package tests

import (
	"testing"

	"idorplus/pkg/client"
)

func TestNewWAFBypass(t *testing.T) {
	headers := map[string]string{
		"X-Forwarded-For": "127.0.0.1",
	}

	waf := client.NewWAFBypass(true, "aggressive", headers)

	if !waf.Enabled {
		t.Error("WAF bypass should be enabled")
	}

	if waf.Mode != "aggressive" {
		t.Errorf("Expected mode aggressive, got %s", waf.Mode)
	}

	if len(waf.Headers) != 1 {
		t.Errorf("Expected 1 header, got %d", len(waf.Headers))
	}
}

func TestSessionManager(t *testing.T) {
	sm := client.NewSessionManager()

	// Add session
	sm.AddSession("test", "session=abc123; token=xyz")

	// Get session
	session := sm.GetSession("test")
	if session == nil {
		t.Fatal("Session should not be nil")
	}

	if session.Name != "test" {
		t.Errorf("Expected session name 'test', got %s", session.Name)
	}

	if len(session.Cookies) != 2 {
		t.Errorf("Expected 2 cookies, got %d", len(session.Cookies))
	}

	// Get non-existent session
	nonExistent := sm.GetSession("fake")
	if nonExistent != nil {
		t.Error("Non-existent session should be nil")
	}
}

func TestProxyManager(t *testing.T) {
	proxies := []string{
		"http://proxy1:8080",
		"http://proxy2:8080",
		"http://proxy3:8080",
	}

	pm := client.NewProxyManager(proxies)

	if pm.Count() != 3 {
		t.Errorf("Expected 3 proxies, got %d", pm.Count())
	}

	if !pm.IsEnabled() {
		t.Error("Proxy manager should be enabled")
	}

	// Test rotation
	first := pm.GetNext()
	second := pm.GetNext()

	if first.String() == second.String() {
		t.Error("Proxy rotation should return different proxies")
	}
}

func TestProxyManagerEmpty(t *testing.T) {
	pm := client.NewProxyManager([]string{})

	if pm.IsEnabled() {
		t.Error("Empty proxy manager should be disabled")
	}

	if pm.GetNext() != nil {
		t.Error("Empty proxy manager should return nil")
	}
}
