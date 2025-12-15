package client

import (
	"crypto/tls"
	"time"

	"idorplus/pkg/utils"

	"github.com/go-resty/resty/v2"
)

type SmartClient struct {
	client    *resty.Client
	wafBypass *WAFBypass
	sessions  *SessionManager
}

func NewSmartClient(config *utils.Config) *SmartClient {
	r := resty.New()

	// Set custom transport
	r.SetTransport(NewCustomTransport())

	// Set timeouts and retries
	timeout, _ := time.ParseDuration(config.Scanner.Timeout)
	r.SetTimeout(timeout)
	r.SetRetryCount(config.Scanner.MaxRetries)

	// Disable TLS verification (handled in transport, but good to be explicit)
	r.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})

	// Initialize WAF Bypass
	waf := NewWAFBypass(
		config.WAFBypass.Enabled,
		config.WAFBypass.Mode,
		config.WAFBypass.Headers,
	)

	return &SmartClient{
		client:    r,
		wafBypass: waf,
		sessions:  NewSessionManager(),
	}
}

func (c *SmartClient) Request() *resty.Request {
	req := c.client.R()

	// Apply WAF Bypass middleware logic manually before sending
	// Note: Since resty doesn't expose the underlying http.Request easily before Send,
	// we set headers directly on the resty Request.

	if c.wafBypass.Enabled {
		// 1. Inject Headers
		for k, v := range c.wafBypass.Headers {
			req.SetHeader(k, v)
		}

		// 2. Rotate UA (Simple implementation)
		// Ideally this should be per-request random
		// For now we just pick one from the list
		if len(c.wafBypass.UserAgents) > 0 {
			req.SetHeader("User-Agent", c.wafBypass.UserAgents[0])
		}

		if c.wafBypass.Mode == "aggressive" {
			req.SetHeader("X-Originating-IP", "127.0.0.1")
			req.SetHeader("X-Remote-IP", "127.0.0.1")
		}
	}

	return req
}

func (c *SmartClient) GetSessionManager() *SessionManager {
	return c.sessions
}
