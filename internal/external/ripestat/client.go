// Package ripestat implements external.GlobalVisibilityProvider on top of the
// RIPEstat Data API looking-glass data call.
//
// See https://stat.ripe.net/docs/02.data-api/looking-glass.html — the call is
// exact-match on the queried prefix and returns, per RIS route collector, the
// routes each of its peers currently holds.
//
// The client is a good citizen by construction: every lookup goes through an
// in-memory per-prefix cache and a per-instance token bucket, so a flapping
// route cannot turn into a query storm against RIPEstat.
package ripestat

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
)

// Provider name reported in results and on the metrics `source` label.
const ProviderName = "ripestat"

// Defaults applied when Config leaves a field zero.
const (
	DefaultBaseURL         = "https://stat.ripe.net"
	DefaultTimeout         = 5 * time.Second
	DefaultCacheTTL        = 60 * time.Second
	DefaultRateLimitPerMin = 10
)

const (
	lookingGlassPath = "/data/looking-glass/data.json"
	// sourceApp identifies RAVEN to RIPEstat, as their fair-use guidance asks.
	sourceApp = "raven"
	userAgent = "raven/bgp-routing-security-monitor"
	// maxResponseBytes caps how much of a response we will read. Busy
	// prefixes return a few hundred KB; this is a guard against a
	// pathological or hostile endpoint, not a tuning knob.
	maxResponseBytes = 16 << 20
)

// ErrRateLimited is returned when the local token bucket rejects a lookup.
// It is a local decision, not a RIPEstat response, and resolves to
// ConsensusInconclusive upstream.
//
// It aliases external.ErrRateLimited so Correlate can recognise the
// suppression without importing this package, and so callers may keep
// matching on either name.
var ErrRateLimited = external.ErrRateLimited

// Config configures a Client. Zero fields take the package defaults.
type Config struct {
	// BaseURL is the RIPEstat origin, without the data-call path. Overridable
	// so tests and staging can point at a stub server.
	BaseURL string
	// Timeout bounds a single HTTP lookup.
	Timeout time.Duration
	// CacheTTL is how long a fetched summary stays usable.
	CacheTTL time.Duration
	// RateLimitPerMin is the sustained lookup budget per minute, and also the
	// burst capacity.
	RateLimitPerMin int

	// HTTPClient replaces the default client. Tests use this to avoid the
	// network; when set, Timeout is not applied to it.
	HTTPClient *http.Client
	// Clock replaces time.Now for the cache and rate limiter. Tests use this
	// to advance time deterministically.
	Clock func() time.Time
}

// Client is a caching, rate-limited RIPEstat looking-glass client.
// It is safe for concurrent use.
type Client struct {
	baseURL  string
	http     *http.Client
	cacheTTL time.Duration
	now      func() time.Time
	limiter  *tokenBucket

	mu    sync.Mutex
	cache map[netip.Prefix]cacheEntry
}

type cacheEntry struct {
	summary   external.GlobalOriginSummary
	fetchedAt time.Time
}

// New builds a Client, applying defaults and validating the base URL.
func New(cfg Config) (*Client, error) {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base-url %q: %w", cfg.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid base-url %q: scheme must be http or https", cfg.BaseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("invalid base-url %q: missing host", cfg.BaseURL)
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultCacheTTL
	}
	rate := cfg.RateLimitPerMin
	if rate <= 0 {
		rate = DefaultRateLimitPerMin
	}
	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}

	return &Client{
		baseURL:  baseURL,
		http:     httpClient,
		cacheTTL: cacheTTL,
		now:      now,
		limiter:  newTokenBucket(float64(rate), now),
		cache:    make(map[netip.Prefix]cacheEntry),
	}, nil
}

// Name implements external.GlobalVisibilityProvider.
func (c *Client) Name() string { return ProviderName }

// GlobalOrigins implements external.GlobalVisibilityProvider.
//
// A cached answer younger than maxAge (default: the configured cache TTL) is
// returned without consuming a rate-limit token or touching the network, and
// is flagged CacheHit so the caller can tell it apart from a live fetch.
// Empty results are cached too, so a prefix nobody carries is not re-queried
// on every event.
func (c *Client) GlobalOrigins(
	ctx context.Context,
	prefix netip.Prefix,
	maxAge time.Duration,
) (external.GlobalOriginSummary, error) {
	if !prefix.IsValid() {
		return external.GlobalOriginSummary{}, fmt.Errorf("invalid prefix")
	}
	prefix = prefix.Masked()

	if maxAge <= 0 {
		maxAge = c.cacheTTL
	}
	// An entry is never usable past the client's own TTL, however relaxed the
	// caller's freshness requirement is.
	if maxAge > c.cacheTTL {
		maxAge = c.cacheTTL
	}

	if summary, ok := c.lookupCache(prefix, maxAge); ok {
		return summary, nil
	}

	if !c.limiter.allow() {
		return external.GlobalOriginSummary{}, ErrRateLimited
	}

	summary, err := c.fetch(ctx, prefix)
	if err != nil {
		return external.GlobalOriginSummary{}, err
	}

	c.storeCache(prefix, summary)
	return summary, nil
}

func (c *Client) lookupCache(prefix netip.Prefix, maxAge time.Duration) (external.GlobalOriginSummary, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[prefix]
	if !ok {
		return external.GlobalOriginSummary{}, false
	}
	age := c.now().Sub(entry.fetchedAt)
	if age < 0 || age >= maxAge {
		if age >= c.cacheTTL {
			delete(c.cache, prefix)
		}
		return external.GlobalOriginSummary{}, false
	}
	// Flag the copy handed to the caller, not the stored entry: CacheHit is a
	// property of this lookup, and the entry must stay unflagged for whoever
	// reads it next.
	summary := entry.summary
	summary.CacheHit = true
	return summary, true
}

func (c *Client) storeCache(prefix netip.Prefix, summary external.GlobalOriginSummary) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	// Opportunistically drop entries that have aged out, so a long-running
	// daemon querying many prefixes does not grow the map without bound.
	for p, e := range c.cache {
		if now.Sub(e.fetchedAt) >= c.cacheTTL {
			delete(c.cache, p)
		}
	}
	// Store the answer as it came off the wire. lookupCache sets CacheHit on
	// the way out, so persisting it here would mark every later reader's
	// answer — including the live fetch this entry came from — incorrectly.
	summary.CacheHit = false
	c.cache[prefix] = cacheEntry{summary: summary, fetchedAt: now}
}

func (c *Client) fetch(ctx context.Context, prefix netip.Prefix) (external.GlobalOriginSummary, error) {
	params := url.Values{
		"resource":  {prefix.String()},
		"sourceapp": {sourceApp},
	}
	endpoint := c.baseURL + lookingGlassPath + "?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return external.GlobalOriginSummary{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return external.GlobalOriginSummary{}, fmt.Errorf("query RIPEstat: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return external.GlobalOriginSummary{}, fmt.Errorf("RIPEstat returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return external.GlobalOriginSummary{}, fmt.Errorf("read response: %w", err)
	}
	return summarize(body)
}
