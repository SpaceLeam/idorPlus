package client

import (
	"context"
	"crypto/tls"
	"math/rand"
	"sync"
	"time"

	"idorplus/pkg/utils"

	"github.com/go-resty/resty/v2"
)

// SmartClient is a production-grade HTTP client with WAF bypass capabilities
type SmartClient struct {
	client       *resty.Client
	wafBypass    *WAFBypass
	sessions     *SessionManager
	rateLimiter  *RateLimiter
	proxyManager *ProxyManager
	config       *utils.Config
	mu           sync.RWMutex
	userAgents   []string
}

// NewSmartClient creates a new smart client with all production features
func NewSmartClient(config *utils.Config) *SmartClient {
	r := resty.New()

	// Set custom transport with TLS spoofing
	r.SetTransport(NewCustomTransport())

	// Parse and set timeout
	timeout := 10 * time.Second
	if config != nil && config.Scanner.Timeout != "" {
		if t, err := time.ParseDuration(config.Scanner.Timeout); err == nil {
			timeout = t
		}
	}
	r.SetTimeout(timeout)

	// Set retry count
	maxRetries := 3
	if config != nil && config.Scanner.MaxRetries > 0 {
		maxRetries = config.Scanner.MaxRetries
	}
	r.SetRetryCount(maxRetries)
	r.SetRetryWaitTime(500 * time.Millisecond)
	r.SetRetryMaxWaitTime(5 * time.Second)

	// Disable TLS verification for testing
	r.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	// Initialize WAF Bypass
	var wafMode string
	var wafHeaders map[string]string
	wafEnabled := true

	if config != nil {
		wafMode = config.WAFBypass.Mode
		wafHeaders = config.WAFBypass.Headers
		wafEnabled = config.WAFBypass.Enabled
	}

	waf := NewWAFBypass(wafEnabled, wafMode, wafHeaders)

	// Parse delay for rate limiter
	minDelay := 100 * time.Millisecond
	maxDelay := 500 * time.Millisecond
	rps := 10

	if config != nil {
		if config.Scanner.Delay != "" {
			if d, err := time.ParseDuration(config.Scanner.Delay); err == nil {
				minDelay = d
				maxDelay = d * 3
			}
		}
		if config.Scanner.Threads > 0 {
			rps = config.Scanner.Threads * 2
		}
	}

	// Initialize rate limiter
	rateLimiter := NewRateLimiter(rps, minDelay, maxDelay)

	// Initialize proxy manager (empty by default)
	proxyManager := NewProxyManager([]string{})

	// User agents for rotation
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}

	return &SmartClient{
		client:       r,
		wafBypass:    waf,
		sessions:     NewSessionManager(),
		rateLimiter:  rateLimiter,
		proxyManager: proxyManager,
		config:       config,
		userAgents:   userAgents,
	}
}

// Request creates a new request with WAF bypass headers applied
func (c *SmartClient) Request() *resty.Request {
	req := c.client.R()

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Apply WAF Bypass
	if c.wafBypass.Enabled {
		// Inject bypass headers
		for k, v := range c.wafBypass.Headers {
			req.SetHeader(k, v)
		}

		// Rotate User-Agent
		if len(c.userAgents) > 0 {
			ua := c.userAgents[rand.Intn(len(c.userAgents))]
			req.SetHeader("User-Agent", ua)
		}

		// Aggressive mode headers
		if c.wafBypass.Mode == "aggressive" {
			req.SetHeader("X-Originating-IP", "127.0.0.1")
			req.SetHeader("X-Remote-IP", "127.0.0.1")
			req.SetHeader("X-Client-IP", "127.0.0.1")
			req.SetHeader("True-Client-IP", "127.0.0.1")
			req.SetHeader("Cluster-Client-IP", "127.0.0.1")
			req.SetHeader("X-Forwarded-Host", "localhost")
		}
	}

	return req
}

// RequestWithRateLimit creates a request after waiting for rate limit
func (c *SmartClient) RequestWithRateLimit(ctx context.Context) (*resty.Request, error) {
	if err := c.rateLimiter.Wait(ctx); err != nil {
		return nil, err
	}
	return c.Request(), nil
}

// GetSessionManager returns the session manager
func (c *SmartClient) GetSessionManager() *SessionManager {
	return c.sessions
}

// GetRateLimiter returns the rate limiter
func (c *SmartClient) GetRateLimiter() *RateLimiter {
	return c.rateLimiter
}

// GetProxyManager returns the proxy manager
func (c *SmartClient) GetProxyManager() *ProxyManager {
	return c.proxyManager
}

// SetProxies sets the proxy list for rotation
func (c *SmartClient) SetProxies(proxies []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.proxyManager = NewProxyManager(proxies)

	// Update transport with proxy
	if c.proxyManager.IsEnabled() {
		transport := NewCustomTransport()
		transport.Proxy = c.proxyManager.GetProxyFunc()
		c.client.SetTransport(transport)
	}
}

// SetWAFBypassMode changes the WAF bypass mode
func (c *SmartClient) SetWAFBypassMode(mode string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wafBypass.Mode = mode
}

// SetDefaultHeader sets a default header for all requests
func (c *SmartClient) SetDefaultHeader(key, value string) {
	c.client.SetHeader(key, value)
}
