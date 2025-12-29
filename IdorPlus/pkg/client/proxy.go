package client

import (
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
)

// ProxyManager handles proxy rotation for evasion
type ProxyManager struct {
	proxies []*url.URL
	current uint64
	mu      sync.RWMutex
	enabled bool
}

// NewProxyManager creates a proxy manager from a list of proxy URLs
// Format: http://user:pass@host:port or socks5://host:port
func NewProxyManager(proxyList []string) *ProxyManager {
	pm := &ProxyManager{
		proxies: make([]*url.URL, 0),
		enabled: len(proxyList) > 0,
	}

	for _, p := range proxyList {
		if u, err := url.Parse(p); err == nil {
			pm.proxies = append(pm.proxies, u)
		}
	}

	return pm
}

// GetNext returns the next proxy in rotation (round-robin)
func (pm *ProxyManager) GetNext() *url.URL {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	if len(pm.proxies) == 0 {
		return nil
	}

	idx := atomic.AddUint64(&pm.current, 1) - 1
	return pm.proxies[idx%uint64(len(pm.proxies))]
}

// GetProxyFunc returns a function suitable for http.Transport.Proxy
func (pm *ProxyManager) GetProxyFunc() func(*http.Request) (*url.URL, error) {
	if !pm.enabled || len(pm.proxies) == 0 {
		return nil
	}

	return func(r *http.Request) (*url.URL, error) {
		return pm.GetNext(), nil
	}
}

// AddProxy adds a new proxy to the rotation
func (pm *ProxyManager) AddProxy(proxyURL string) error {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.proxies = append(pm.proxies, u)
	pm.enabled = true
	return nil
}

// RemoveProxy removes a proxy from the rotation
func (pm *ProxyManager) RemoveProxy(proxyURL string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i, p := range pm.proxies {
		if p.String() == proxyURL {
			pm.proxies = append(pm.proxies[:i], pm.proxies[i+1:]...)
			break
		}
	}

	pm.enabled = len(pm.proxies) > 0
}

// Count returns the number of proxies
func (pm *ProxyManager) Count() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.proxies)
}

// IsEnabled returns whether proxy rotation is enabled
func (pm *ProxyManager) IsEnabled() bool {
	return pm.enabled
}
