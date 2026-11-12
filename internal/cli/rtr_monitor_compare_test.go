package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// testSettle is the settle window the comparison tests set with
// --compare-settle.
const testSettle = 750 * time.Millisecond

// compareRun is rtr monitor with several caches, as RunE wires it
// (newMonitorSet, consumeRTREvents with the comparison), against fake caches.
type compareRun struct {
	*monitorRun
	srvs []*rtrtest.Server
	set  *monitorSet
}

// runCompare starts rtr monitor against srvs, one --cache each, with
// --compare-settle settle.
func runCompare(t *testing.T, srvs []*rtrtest.Server, settle time.Duration, detector *telemetry.Detector) *compareRun {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := &monitorRun{ndjson: &lockedBuffer{}}
	rec := telemetry.NewRecorder(m.ndjson, 256, quiet)
	var caches []string
	for _, s := range srvs {
		caches = append(caches, s.Addr())
	}
	set, err := newMonitorSet(caches, "tcp", "auto", settle, rec, quiet)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range caches {
		initAnomalyMetrics(c)
	}
	consumed := make(chan struct{})
	go func() {
		defer close(consumed)
		consumeRTREvents(rec, detector, set.cmp, nil, quiet)
	}()
	ctx, cancel := context.WithCancel(context.Background())
	done := set.start(ctx)
	var once sync.Once
	m.stop = func() {
		once.Do(func() {
			cancel()
			<-done // Record must not run after Close
			rec.Close()
			<-consumed
		})
	}
	t.Cleanup(m.stop)
	r := &compareRun{monitorRun: m, srvs: srvs, set: set}
	for _, s := range srvs {
		r.waitSyncs(t, s, 1, 5*time.Second)
	}
	return r
}

// of returns the records of eventType about srv's cache.
func (r *compareRun) of(t *testing.T, eventType string, srv *rtrtest.Server) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, rec := range r.records(t, eventType) {
		if rec["cache"] == srv.Addr() {
			out = append(out, rec)
		}
	}
	return out
}

// waitSyncs waits until srv's cache has n sync records.
func (r *compareRun) waitSyncs(t *testing.T, srv *rtrtest.Server, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for len(r.of(t, "sync", srv)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s: fewer than %d syncs within %v; NDJSON:\n%s", srv.Addr(), n, timeout, r.ndjson)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// advance applies d at srv as its next serial, notifies, and waits for the
// monitor's sync of it.
func (r *compareRun) advance(t *testing.T, srv *rtrtest.Server, d rtrtest.Delta) {
	t.Helper()
	n := len(r.of(t, "sync", srv))
	srv.Advance(d)
	srv.Notify()
	r.waitSyncs(t, srv, n+1, 5*time.Second)
}

// tick makes srv's cache complete a sync with no change, so the caches are
// compared again.
func (r *compareRun) tick(t *testing.T, srv *rtrtest.Server) { r.advance(t, srv, rtrtest.Delta{}) }

// outlast waits until differences seen so far are past the settle window.
func outlast() { time.Sleep(testSettle + 150*time.Millisecond) }

// waitTracked waits until the comparison attributes n differences of kind
// to srv's cache (settled or not).
func (r *compareRun) waitTracked(t *testing.T, srv *rtrtest.Server, kind string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.set.cmp.Tracked()[srv.Addr()][kind] != n {
		if time.Now().After(deadline) {
			t.Fatalf("%s: tracked %v, want %d %s", srv.Addr(), r.set.cmp.Tracked()[srv.Addr()], n, kind)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func newCaches(t *testing.T, versions ...uint8) []*rtrtest.Server {
	var out []*rtrtest.Server
	for _, v := range versions {
		out = append(out, rtrtest.NewServer(t, monitorCache(v)))
	}
	return out
}

func setAll(srvs []*rtrtest.Server, vrps []rtrtest.VRP, aspas []rtrtest.ASPASet) {
	for _, s := range srvs {
		s.SetData(vrps, aspas)
	}
}

// counts returns a divergence record's counts.
func counts(rec map[string]any) map[string]float64 {
	out := map[string]float64{}
	for k, v := range rec["counts"].(map[string]any) {
		out[k] = v.(float64)
	}
	return out
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func addrs(srvs ...*rtrtest.Server) []string {
	var out []string
	for _, s := range srvs {
		out = append(out, s.Addr())
	}
	return out
}

// divergentGauge reads raven_rtr_divergent_items{cache,kind}, -1 if absent.
func divergentGauge(cache, kind string) float64 {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return -1
	}
	for _, mf := range mfs {
		if mf.GetName() != "raven_rtr_divergent_items" {
			continue
		}
		for _, m := range mf.GetMetric() {
			l := map[string]string{}
			for _, lp := range m.GetLabel() {
				l[lp.GetName()] = lp.GetValue()
			}
			if l["cache"] == cache && l["kind"] == kind {
				return m.GetGauge().GetValue()
			}
		}
	}
	return -1
}

// waitGauge waits until the gauge name{cache} is want.
func waitGauge(t *testing.T, name, cache string, want float64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for rtrtest.Gauge(name, cache) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s{cache=%q} = %v, want %v", name, cache, rtrtest.Gauge(name, cache), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

var (
	baseVRPs  = rtrtest.GenVRPs(0, 50, 65001)
	extraVRPs = rtrtest.GenVRPs(5000, 5, 65002)
)

// A cache that lags the others by less than the settle window is not a
// divergence: the difference is seen, then gone before it settles.
func TestCompareLagWithinSettle(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, nil)
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	d := rtrtest.Delta{AnnounceVRPs: extraVRPs}
	r.advance(t, a, d)
	r.advance(t, b, d)
	r.waitTracked(t, c, telemetry.DivergenceVRPMissing, 5) // the lag is seen
	r.advance(t, c, d)                                     // and caught up within the window
	outlast()
	r.tick(t, a)
	r.stop()

	if n := len(r.records(t, "divergence")) + len(r.records(t, "divergence_resolved")); n != 0 {
		t.Errorf("%d divergence records for a lag within the settle window, want none; NDJSON:\n%s", n, r.ndjson)
	}
}

// A cache persistently missing VRPs: one divergence record naming it, for
// the episode (not one per VRP), then divergence_resolved once it catches
// up. The gauge follows.
func TestCompareMissingThenResolved(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, nil)
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	d := rtrtest.Delta{AnnounceVRPs: extraVRPs}
	r.advance(t, a, d)
	r.advance(t, b, d)
	outlast()
	r.tick(t, a)
	r.waitRecords(t, "divergence", 1)
	if g := divergentGauge(c.Addr(), telemetry.DivergenceVRPMissing); g != 5 {
		t.Errorf("raven_rtr_divergent_items{kind=vrp_missing} at the lagging cache = %v, want 5", g)
	}
	if g := divergentGauge(a.Addr(), telemetry.DivergenceVRPMissing); g != 0 {
		t.Errorf("raven_rtr_divergent_items{kind=vrp_missing} at a cache in the majority = %v, want 0", g)
	}
	r.advance(t, c, d)
	r.waitRecords(t, "divergence_resolved", 1)
	r.stop()

	divs := r.records(t, "divergence")
	if len(divs) != 1 {
		t.Fatalf("%d divergence records, want 1 (one per episode); NDJSON:\n%s", len(divs), r.ndjson)
	}
	dv := divs[0]
	if dv["cache"] != c.Addr() || !reflect.DeepEqual(counts(dv), map[string]float64{"vrp_missing": 5}) || dv["episode"] != 1.0 {
		t.Errorf("divergence %v, want vrp_missing 5 at %s, episode 1", dv, c.Addr())
	}
	samples := dv["samples"].([]any)
	if len(samples) != 5 {
		t.Fatalf("%d samples, want 5", len(samples))
	}
	s0 := samples[0].(map[string]any)
	// GenVRPs numbers addresses, so its /24s keep host bits.
	if s0["kind"] != "vrp_missing" || s0["prefix"] != "10.0.19.136/24" || s0["asn"] != 65002.0 || s0["max_length"] != 24.0 ||
		!slices.Equal(strs(s0["agree"]), addrs(c)) || !slices.Equal(strs(s0["disagree"]), addrs(a, b)) {
		t.Errorf("first sample %v, want 10.0.19.136/24 AS65002 missing, agree [C], disagree [A B]", s0)
	}
	if !slices.Equal(strs(dv["compared"]), addrs(a, b, c)) || dv["settle_ns"] != float64(testSettle) {
		t.Errorf("compared %v settle %v, want all three and %d", dv["compared"], dv["settle_ns"], testSettle)
	}
	started, _ := time.Parse(time.RFC3339Nano, dv["started_at"].(string))
	at, _ := time.Parse(time.RFC3339Nano, dv["timestamp"].(string))
	if at.Sub(started) <= testSettle {
		t.Errorf("divergence at %v, started %v: reported within the settle window", at, started)
	}

	res := r.records(t, "divergence_resolved")
	if len(res) != 1 || res[0]["cache"] != c.Addr() || res[0]["episode"] != 1.0 || res[0]["started_at"] != dv["started_at"] {
		t.Errorf("divergence_resolved %v, want one for %s episode 1 started %v", res, c.Addr(), dv["started_at"])
	}
	if g := divergentGauge(c.Addr(), telemetry.DivergenceVRPMissing); g != 0 {
		t.Errorf("gauge after resolution = %v, want 0", g)
	}
}

// A cache with extra VRPs: divergence (vrp_extra) at that cache.
func TestCompareExtra(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, nil)
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	r.advance(t, c, rtrtest.Delta{AnnounceVRPs: extraVRPs})
	outlast()
	r.tick(t, a)
	r.waitRecords(t, "divergence", 1)
	r.stop()
	divs := r.records(t, "divergence")
	if len(divs) != 1 || divs[0]["cache"] != c.Addr() || !reflect.DeepEqual(counts(divs[0]), map[string]float64{"vrp_extra": 5}) {
		t.Fatalf("divergence records %v, want one: vrp_extra 5 at %s", divs, c.Addr())
	}
	s0 := divs[0]["samples"].([]any)[0].(map[string]any)
	if !slices.Equal(strs(s0["agree"]), addrs(c)) || !slices.Equal(strs(s0["disagree"]), addrs(a, b)) {
		t.Errorf("sample %v, want agree [C] disagree [A B]", s0)
	}
	if _, ok := divs[0]["split_with"]; ok {
		t.Errorf("split_with on a divergence with no split: %v", divs[0])
	}
}

// Two caches that differ have no majority: split, at both, each naming the
// other.
func TestCompareSplit(t *testing.T) {
	s := newCaches(t, 2, 2)
	a, b := s[0], s[1]
	setAll(s, baseVRPs, nil)
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	r.advance(t, a, rtrtest.Delta{AnnounceVRPs: extraVRPs})
	outlast()
	r.tick(t, b)
	r.waitRecords(t, "divergence", 2)
	r.stop()
	divs := r.records(t, "divergence")
	if len(divs) != 2 {
		t.Fatalf("%d divergence records, want 2; NDJSON:\n%s", len(divs), r.ndjson)
	}
	for _, dv := range divs {
		other := a
		if dv["cache"] == a.Addr() {
			other = b
		}
		if !reflect.DeepEqual(counts(dv), map[string]float64{"vrp_split": 5}) || !slices.Equal(strs(dv["split_with"]), addrs(other)) {
			t.Errorf("divergence %v, want vrp_split 5, split_with [%s]", dv, other.Addr())
		}
		s0 := dv["samples"].([]any)[0].(map[string]any)
		if !slices.Equal(strs(s0["agree"]), []string{dv["cache"].(string)}) || !slices.Equal(strs(s0["disagree"]), addrs(other)) {
			t.Errorf("sample %v, want both sides named", s0)
		}
	}
}

// An ASPA provider set that differs at one cache: divergence for that
// customer AS at that cache.
func TestCompareASPAProviderSet(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	good := []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501, 64502}}, {Customer: 64510, Providers: []uint32{64511}}}
	a.SetData(baseVRPs, good)
	b.SetData(baseVRPs, good)
	c.SetData(baseVRPs, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}, {Customer: 64510, Providers: []uint32{64511}}})
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))

	outlast()
	r.tick(t, a)
	r.waitRecords(t, "divergence", 1)
	r.stop()
	divs := r.records(t, "divergence")
	if len(divs) != 1 || divs[0]["cache"] != c.Addr() || !reflect.DeepEqual(counts(divs[0]), map[string]float64{"aspa_mismatch": 1}) {
		t.Fatalf("divergence records %v, want one: aspa_mismatch 1 at %s", divs, c.Addr())
	}
	s0 := divs[0]["samples"].([]any)[0].(map[string]any)
	if s0["customer_asn"] != 64500.0 || fmt.Sprint(s0["providers"]) != "[64501]" || fmt.Sprint(s0["majority_providers"]) != "[64501 64502]" {
		t.Errorf("sample %v, want customer 64500, providers [64501], majority [64501 64502]", s0)
	}
}

// The same large withdrawal at all three caches: one upstream_change, the
// per-cache anomalies as before, and no divergence.
func TestCompareUpstreamWithdrawal(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, rtrtest.GenVRPs(0, 1300, 65001), nil)
	r := runCompare(t, s, testSettle, warmDetector(addrs(s...)...))

	wd := rtrtest.Delta{WithdrawVRPs: rtrtest.GenVRPs(0, 1200, 65001)}
	for _, srv := range s {
		r.advance(t, srv, wd)
	}
	r.waitRecords(t, "upstream_change", 1)
	r.waitRecords(t, "anomaly", 3)
	outlast()
	r.tick(t, a)
	r.stop()

	ups := r.records(t, "upstream_change")
	if len(ups) != 1 {
		t.Fatalf("%d upstream_change records, want 1; NDJSON:\n%s", len(ups), r.ndjson)
	}
	up := ups[0]
	if !slices.Equal(strs(up["caches"]), addrs(a, b, c)) || up["overlap"] != 1.0 {
		t.Errorf("upstream_change %v, want all three caches, overlap 1", up)
	}
	for i, ch := range up["changes"].([]any) {
		ch := ch.(map[string]any)
		if ch["cache"] != s[i].Addr() || ch["serial"] != 1.0 || ch["vrp_withdrawn"] != 1200.0 || ch["vrp_announced"] != 0.0 {
			t.Errorf("change %v, want serial 1, 1200 withdrawn at %s", ch, s[i].Addr())
		}
	}
	if samples := up["samples"].([]any); len(samples) != 20 || samples[0].(map[string]any)["change"] != "vrp_withdrawn" {
		t.Errorf("samples %v, want 20 withdrawals", samples)
	}
	for _, srv := range s {
		if n := len(r.of(t, "anomaly", srv)); n != 1 {
			t.Errorf("%s: %d anomaly records, want 1 (the per-cache anomaly stays)", srv.Addr(), n)
		}
	}
	if n := len(r.records(t, "divergence")); n != 0 {
		t.Errorf("%d divergence records, want none; NDJSON:\n%s", n, r.ndjson)
	}
}

// The same large withdrawal at one cache only: its anomaly, and a
// divergence (missing) at it once settled, never an upstream_change.
func TestCompareOneCacheWithdrawal(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b := s[0], s[1]
	setAll(s, rtrtest.GenVRPs(0, 1300, 65001), nil)
	r := runCompare(t, s, testSettle, warmDetector(addrs(s...)...))

	r.advance(t, a, rtrtest.Delta{WithdrawVRPs: rtrtest.GenVRPs(0, 1200, 65001)})
	r.waitRecords(t, "anomaly", 1)
	outlast()
	r.tick(t, b)
	r.waitRecords(t, "divergence", 1)
	r.stop()

	if n := len(r.records(t, "upstream_change")); n != 0 {
		t.Errorf("%d upstream_change records for a change at one cache, want none; NDJSON:\n%s", n, r.ndjson)
	}
	divs := r.records(t, "divergence")
	if len(divs) != 1 || divs[0]["cache"] != a.Addr() || !reflect.DeepEqual(counts(divs[0]), map[string]float64{"vrp_missing": 1200}) ||
		len(divs[0]["samples"].([]any)) != 20 {
		t.Errorf("divergence records %v, want one: vrp_missing 1200 at %s, 20 samples", divs, a.Addr())
	}
	if n := len(r.of(t, "anomaly", a)); n != 1 {
		t.Errorf("%d anomaly records at the cache, want 1", n)
	}
}

// A cache that disconnects leaves the comparison: the others moving on
// without it is not a divergence at it. It comes back with a full sync and
// joins again, with no false records.
func TestCompareDisconnectedCacheLeavesAndReturns(t *testing.T) {
	s := newCaches(t, 2, 2, 2)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, nil)
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))
	for _, srv := range s {
		waitGauge(t, "raven_rtr_compared", srv.Addr(), 1)
	}

	c.Session().Close()
	r.waitDisconnect(t, "eof")
	waitGauge(t, "raven_rtr_compared", c.Addr(), 0)
	if g := rtrtest.Gauge("raven_rtr_compared", a.Addr()); g != 1 {
		t.Errorf("raven_rtr_compared for a connected cache = %v, want 1", g)
	}
	d := rtrtest.Delta{AnnounceVRPs: extraVRPs}
	c.Advance(d) // for when it comes back
	r.advance(t, a, d)
	r.advance(t, b, d)
	outlast()
	r.tick(t, a)
	if tr := r.set.cmp.Tracked(); len(tr) != 0 {
		t.Errorf("differences tracked with the cache disconnected: %v", tr)
	}
	if g := rtrtest.Gauge("raven_rtr_compared", c.Addr()); g != 0 {
		t.Errorf("raven_rtr_compared before the cache's next sync = %v, want 0", g)
	}
	r.waitSyncs(t, c, 2, 15*time.Second) // the client retries after 5s
	waitGauge(t, "raven_rtr_compared", c.Addr(), 1)
	outlast()
	r.tick(t, a)
	r.stop()
	if n := len(r.records(t, "divergence")) + len(r.records(t, "divergence_resolved")); n != 0 {
		t.Errorf("%d divergence records around a disconnect, want none; NDJSON:\n%s", n, r.ndjson)
	}
}

// A cache at RTR version 1 serves no ASPA: it is compared on VRPs only.
func TestCompareV1CacheVRPsOnly(t *testing.T) {
	s := newCaches(t, 2, 2, 1)
	a, b, c := s[0], s[1], s[2]
	setAll(s, baseVRPs, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}, {Customer: 64510, Providers: []uint32{64511}}})
	r := runCompare(t, s, testSettle, telemetry.NewDetector(telemetry.DefaultAnomalyConfig()))
	if v := r.set.clients[2].ProtocolVersion(); v != 1 {
		t.Fatalf("third cache at version %d, want 1", v)
	}

	outlast()
	r.tick(t, a) // the v1 cache's missing ASPAs must not count
	d := rtrtest.Delta{AnnounceVRPs: extraVRPs}
	r.advance(t, a, d)
	r.advance(t, b, d)
	outlast()
	r.tick(t, a)
	r.waitRecords(t, "divergence", 1)
	r.stop()
	divs := r.records(t, "divergence")
	if len(divs) != 1 || divs[0]["cache"] != c.Addr() || !reflect.DeepEqual(counts(divs[0]), map[string]float64{"vrp_missing": 5}) {
		t.Errorf("divergence records %v, want one: vrp_missing 5 at the v1 cache %s, nothing on ASPA", divs, c.Addr())
	}
}

// With a single --cache, rtr monitor writes what it wrote before the
// comparison existed: the same scenario through newMonitorSet and through
// the client and consumer alone gives the same records.
func TestCompareSingleCacheOutputUnchanged(t *testing.T) {
	scenario := func(t *testing.T, viaSet bool) []string {
		srv := rtrtest.NewServer(t, monitorCache(2))
		srv.SetData(baseVRPs, []rtrtest.ASPASet{{Customer: 64500, Providers: []uint32{64501}}})
		var m *monitorRun
		if viaSet {
			r := runCompare(t, []*rtrtest.Server{srv}, 0, warmDetector(srv.Addr()))
			if r.set.cmp != nil {
				t.Fatal("a comparison with one cache")
			}
			m = r.monitorRun
		} else {
			m = runMonitorWith(t, srv, "auto", nil, warmDetector(srv.Addr()))
			m.waitRecords(t, "sync", 1)
		}
		srv.Advance(rtrtest.Delta{AnnounceVRPs: rtrtest.GenVRPs(1000, 1200, 65002), WithdrawVRPs: rtrtest.GenVRPs(0, 3, 65001)})
		srv.Notify()
		m.waitRecords(t, "anomaly", 1)
		srv.Session().Send(rtrtest.CacheReset(2))
		m.waitRecords(t, "sync", 3)
		m.waitRecords(t, "anomaly", 2)
		srv.Session().Close()
		m.waitDisconnect(t, "eof")
		m.stop()
		var out []string
		for _, line := range strings.Split(strings.TrimSpace(m.ndjson.String()), "\n") {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatal(err)
			}
			// What differs run to run: times, durations, the address.
			for _, f := range []string{"timestamp", "sync_duration_ns", "interval_since_ns", "error_text"} {
				delete(rec, f)
			}
			rec["cache"] = "C"
			for _, f := range []string{"raw", "z_scores"} {
				if mm, ok := rec[f].(map[string]any); ok {
					delete(mm, "interval_since_ns")
					delete(mm, "sync_duration_ns")
				}
			}
			b, _ := json.Marshal(rec)
			out = append(out, string(b))
		}
		sort.Strings(out)
		return out
	}
	before, after := scenario(t, false), scenario(t, true)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("one --cache: records differ\nbefore:\n%s\nafter:\n%s", strings.Join(before, "\n"), strings.Join(after, "\n"))
	}
}

// --cache given twice is refused.
func TestCompareDuplicateCache(t *testing.T) {
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := newMonitorSet([]string{"a:323", "b:323", "a:323"}, "tcp", "auto", 0, nil, quiet); err == nil {
		t.Error("the same --cache twice accepted")
	}
}
