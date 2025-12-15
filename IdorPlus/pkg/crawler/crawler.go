package crawler

import (
	"net/url"
	"strings"

	"idorplus/pkg/client"
)

type Crawler struct {
	Client    *client.SmartClient
	Depth     int
	MaxPages  int
	Visited   map[string]bool
	Endpoints []string
	JSParser  *JSParser
}

func NewCrawler(c *client.SmartClient) *Crawler {
	return &Crawler{
		Client:   c,
		Depth:    2,
		MaxPages: 50,
		Visited:  make(map[string]bool),
		JSParser: NewJSParser(),
	}
}

func (c *Crawler) Crawl(startURL string) []string {
	c.crawlRecursive(startURL, 0)
	return c.Endpoints
}

func (c *Crawler) crawlRecursive(currentURL string, depth int) {
	if depth > c.Depth || len(c.Visited) >= c.MaxPages {
		return
	}
	if c.Visited[currentURL] {
		return
	}
	c.Visited[currentURL] = true

	resp, err := c.Client.Request().Get(currentURL)
	if err != nil {
		return
	}

	body := string(resp.Body())

	// 1. Extract links (Simple regex for now, ideally HTML parser)
	// TODO: Use net/html for robust parsing

	// 2. Extract JS endpoints
	if strings.HasSuffix(currentURL, ".js") || strings.Contains(resp.Header().Get("Content-Type"), "javascript") {
		endpoints := c.JSParser.ParseJS(body)
		for _, ep := range endpoints {
			// Resolve relative URLs
			fullURL := c.resolveURL(currentURL, ep)
			c.Endpoints = append(c.Endpoints, fullURL)
		}
	} else {
		// If HTML, look for scripts and other links
		// Placeholder for full HTML parsing
		c.Endpoints = append(c.Endpoints, currentURL)
	}
}

func (c *Crawler) resolveURL(base, target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	b, err := url.Parse(base)
	if err != nil {
		return target
	}
	return b.ResolveReference(u).String()
}
