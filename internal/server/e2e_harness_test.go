package server

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/api"
	"github.com/nokia/bgp-routing-security-monitor/internal/bmp/bmptest"
	"github.com/nokia/bgp-routing-security-monitor/internal/config"
	"github.com/nokia/bgp-routing-security-monitor/internal/events"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// End-to-end harness: raven serve, in-process (RunContext), with its BMP
// listener and API on 127.0.0.1:0, one RTR cache (rtrtest.Server), the event
// engine's webhooks pointed at an httptest server, FlowSpec in its dry-run
// mode (rules land in the registry; no GoBGP), a fake router (bmptest.Feed)
// and raven watch subscribed through the real API.

// e2e is one running serve and everything around it.
type e2e struct {
	t     *testing.T
	s     *Server
	cache *rtrtest.Server
	feed  *bmptest.Feed
	peer  bmptest.Peer
	hooks *webhookSink
	api   string // base URL of the API

	mu      sync.Mutex
	emitted []events.Event // every event handed to the event engine

	stopOnce sync.Once
	cancel   context.CancelFunc
	done     chan error
}

// e2eConfig is what a test varies.
type e2eConfig struct {
	vrps  []rtrtest.VRP
	aspas []rtrtest.ASPASet
	// rules are the event rules; a webhook action's URL "hook:NAME" is
	// rewritten to the sink, path /NAME.
	rules         []config.RuleConfig
	bulkThreshold int
	// cache, if set, adjusts the fake RTR cache's config.
	cache func(*rtrtest.ServerConfig)
}

// webhookSink is the webhook endpoint: it records every POST.
type webhookSink struct {
	srv   *httptest.Server
	mu    sync.Mutex
	posts []webhookPost
	more  chan struct{}
}

// webhookPost is one delivery: the rule (the URL path) and its payload.
type webhookPost struct {
	Rule string
	Body map[string]any
}

func newWebhookSink(t *testing.T) *webhookSink {
	w := &webhookSink{more: make(chan struct{}, 1)}
	w.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			t.Errorf("webhook body %q: %v", body, err)
		}
		w.mu.Lock()
		w.posts = append(w.posts, webhookPost{Rule: strings.TrimPrefix(r.URL.Path, "/"), Body: m})
		w.mu.Unlock()
		select {
		case w.more <- struct{}{}:
		default:
		}
		rw.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(w.srv.Close)
	return w
}

// matching returns the posts for which keep is true.
func (w *webhookSink) matching(keep func(webhookPost) bool) []webhookPost {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []webhookPost
	for _, p := range w.posts {
		if keep(p) {
			out = append(out, p)
		}
	}
	return out
}

// await waits until at least n posts match keep.
func (w *webhookSink) await(t *testing.T, n int, what string, keep func(webhookPost) bool) []webhookPost {
	t.Helper()
	deadline := time.After(testWaitBound)
	for {
		if got := w.matching(keep); len(got) >= n {
			return got
		}
		select {
		case <-w.more:
		case <-deadline:
			t.Fatalf("%d webhook posts for %s, want %d", len(w.matching(keep)), what, n)
		}
	}
}

// forPrefix keeps the posts about prefix.
func forPrefix(p netip.Prefix) func(webhookPost) bool {
	return func(wp webhookPost) bool { return wp.Body["prefix"] == p.String() }
}

func startE2E(t *testing.T, ec e2eConfig) *e2e {
	t.Helper()
	ccfg := rtrtest.ServerConfig{MaxVersion: 2, Session: 9, Refresh: 3600, Retry: 600, Expire: 7200}
	if ec.cache != nil {
		ec.cache(&ccfg)
	}
	cache := rtrtest.NewServer(t, ccfg)
	cache.SetData(ec.vrps, ec.aspas)
	hooks := newWebhookSink(t)

	cfg := &config.Config{}
	cfg.BMP.Listen = "127.0.0.1:0"
	cfg.API.Listen = "127.0.0.1:0"
	cfg.RTR.Caches = []config.RTRCacheConfig{{Address: cache.Addr()}}
	cfg.RTR.RTRVersion = "auto"
	cfg.Validation.ROV = true
	cfg.Validation.ASPA = true
	cfg.Validation.ASPADefaultProcedure = "upstream"
	cfg.Events.RTRBulkThreshold = ec.bulkThreshold
	for _, rc := range ec.rules {
		for i, ac := range rc.Actions {
			if name, ok := strings.CutPrefix(ac.URL, "hook:"); ok {
				rc.Actions[i].URL = hooks.srv.URL + "/" + name
				rc.Actions[i].MaxAttempts = 1
			}
		}
		cfg.Events.Rules = append(cfg.Events.Rules, rc)
	}

	s, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := &e2e{t: t, s: s, cache: cache, hooks: hooks, done: make(chan error, 1)}
	s.testEmitted = func(ev events.Event) {
		h.mu.Lock()
		h.emitted = append(h.emitted, ev)
		h.mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- s.RunContext(ctx) }()
	t.Cleanup(h.stop)
	select {
	case <-s.listening:
	case err := <-h.done:
		t.Fatalf("serve stopped before listening: %v", err)
	case <-time.After(testWaitBound):
		t.Fatal("serve did not bind its listeners")
	}
	if s.apiAddr == nil {
		t.Fatal("serve has no API listener")
	}
	h.api = "http://" + s.apiAddr.String()

	h.feed = bmptest.Dial(t, s.bmpAddr.String())
	h.feed.Initiation("e2e-router")
	h.peer = bmptest.Peer{Addr: netip.MustParseAddr("198.18.0.1"), ASN: 64501, BGPID: netip.MustParseAddr("198.18.0.1")}
	h.feed.PeerUp(h.peer)
	return h
}

// stop shuts serve down and waits for RunContext to return. Once it has,
// nothing more reaches the webhook sink or the FlowSpec registry: counts
// taken after stop are final.
func (h *e2e) stop() {
	h.stopOnce.Do(func() {
		h.cancel()
		select {
		case err := <-h.done:
			if err != nil {
				h.t.Errorf("serve: %v", err)
			}
		case <-time.After(testWaitBound):
			h.t.Error("serve did not stop")
		}
	})
}

// emittedFor returns the events handed to the event engine about prefix
// (all of them for an invalid prefix), and rtr_bulk_change events.
func (h *e2e) emittedFor(p netip.Prefix) []events.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []events.Event
	for _, ev := range h.emitted {
		if ev.Route != nil && ev.Route.Prefix == p {
			out = append(out, ev)
		}
	}
	return out
}

func (h *e2e) emittedOfType(typ events.EventType) []events.Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []events.Event
	for _, ev := range h.emitted {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

// route returns the table's route for prefix from the feed's peer, if any.
func (h *e2e) route(p netip.Prefix) *types.Route {
	for _, r := range h.s.table.GetByPrefix(p) {
		if r.PeerAddr == h.peer.Addr {
			return r
		}
	}
	return nil
}

// announce announces routes and waits until the table holds each of them.
func (h *e2e) announce(routes ...bmptest.Route) {
	h.t.Helper()
	h.feed.Announce(h.peer, routes...)
	for _, r := range routes {
		waitUntil(h.t, "route "+r.Prefix.String()+" in the table", func() bool {
			got := h.route(r.Prefix)
			return got != nil && len(got.ASPath) == len(r.ASPath) && got.ASPath[len(got.ASPath)-1] == r.ASPath[len(r.ASPath)-1] &&
				len(got.Communities) == len(r.Communities)
		})
	}
}

// rtrUpdate applies d at the cache, announces it with Serial Notify, and
// waits until serve has completed the revalidation pass it causes.
func (h *e2e) rtrUpdate(d rtrtest.Delta) uint32 {
	h.t.Helper()
	passes := h.s.revalidationPasses.Load()
	serial := h.cache.Advance(d)
	h.cache.Notify()
	waitUntil(h.t, "the RTR update's revalidation pass", func() bool {
		return h.s.revalidationPasses.Load() > passes && !h.s.revalidating.Load() &&
			h.s.vrpStore.Serial() == serial
	})
	return serial
}

// ready waits for serve's first RTR sync, after which it ingests BMP.
func (h *e2e) ready() {
	h.t.Helper()
	select {
	case <-h.s.rtrReady:
	case <-time.After(testWaitBound):
		h.t.Fatal("no RTR sync")
	}
}

// e2eMarker is a prefix no test route uses; see watchE2E.until.
var e2eMarker = netip.MustParsePrefix("233.252.0.0/24")

// sendMarker announces the marker route (a new route each time: another
// path). Watch delivers every event notified before it first.
func (h *e2e) sendMarker(n uint32) {
	h.t.Helper()
	h.feed.Announce(h.peer, bmptest.Route{Prefix: e2eMarker, ASPath: []uint32{64501, 64999 + n}})
}

// watchE2E is raven watch through the real API.
type watchE2E struct {
	events chan api.RouteResponse
}

// watch subscribes to /api/v1/watch with the raw query q. The handler
// registers the subscriber before it sends the headers, so once this
// returns every later change reaches it.
func (h *e2e) watch(q string) *watchE2E {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, h.api+"/api/v1/watch?"+q, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { resp.Body.Close() })
	w := &watchE2E{events: make(chan api.RouteResponse, 100_000)}
	go func() {
		defer close(w.events)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			line, ok := strings.CutPrefix(sc.Text(), "data: ")
			if !ok {
				continue
			}
			var rr api.RouteResponse
			if json.Unmarshal([]byte(line), &rr) == nil {
				w.events <- rr
			}
		}
	}()
	return w
}

// until returns the events before the next marker route.
func (w *watchE2E) until(t *testing.T) []api.RouteResponse {
	t.Helper()
	var got []api.RouteResponse
	timeout := time.After(testWaitBound)
	for {
		select {
		case rr, ok := <-w.events:
			if !ok {
				t.Fatal("watch stream ended before the marker")
			}
			if rr.Prefix == e2eMarker.String() {
				return got
			}
			got = append(got, rr)
		case <-timeout:
			t.Fatal("no marker on the watch stream")
		}
	}
}

// forWatchPrefix returns the watch events about prefix.
func forWatchPrefix(evs []api.RouteResponse, p netip.Prefix) []api.RouteResponse {
	var out []api.RouteResponse
	for _, e := range evs {
		if e.Prefix == p.String() {
			out = append(out, e)
		}
	}
	return out
}

// flowspecRules lists the FlowSpec rules through the API.
func (h *e2e) flowspecRules() []api.FlowspecRuleResponse {
	h.t.Helper()
	resp, err := http.Get(h.api + "/api/v1/flowspec/rules")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var rules []api.FlowspecRuleResponse
	if err := json.NewDecoder(resp.Body).Decode(&rules); err != nil {
		h.t.Fatalf("flowspec rules: %v", err)
	}
	return rules
}

// status reads /api/v1/status.
func (h *e2e) status() api.StatusResponse {
	h.t.Helper()
	resp, err := http.Get(h.api + "/api/v1/status")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var st api.StatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		h.t.Fatalf("status: %v", err)
	}
	return st
}

// Rule builders.

func webhookRule(name string, trigger config.TriggerConfig) config.RuleConfig {
	return config.RuleConfig{Name: name, Trigger: trigger,
		Actions: []config.ActionConfig{{Type: "webhook", URL: "hook:" + name}}}
}

func postureChange(postures ...string) config.TriggerConfig {
	return config.TriggerConfig{Type: "posture_change", Postures: postures}
}

// waitTable waits until the table holds n routes, and on timeout lists what
// it holds.
func (h *e2e) waitTable(n int, what string) {
	h.t.Helper()
	deadline := time.Now().Add(testWaitBound)
	for h.s.table.Count() != uint64(n) {
		if time.Now().After(deadline) {
			var held []string
			for _, r := range h.s.table.Snapshot() {
				held = append(held, r.PeerAddr.String()+" "+r.Prefix.String()+" "+r.RIBType.String())
			}
			h.t.Fatalf("timed out waiting for %s: table holds %d routes, want %d: %v", what, h.s.table.Count(), n, held)
		}
		time.Sleep(time.Millisecond)
	}
}
