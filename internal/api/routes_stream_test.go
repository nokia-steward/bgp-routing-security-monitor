package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// largeRoutesServer holds n routes of one peer, 10.0.0.0/24 upwards.
func largeRoutesServer(t *testing.T, n int) *Server {
	t.Helper()
	table := routetable.New()
	for i := range n {
		table.Insert(&types.Route{
			PeerAddr:        netip.MustParseAddr("192.0.2.1"),
			Prefix:          netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)),
			ASPath:          []uint32{64500, 64501},
			RIBType:         types.LocRIB,
			SecurityPosture: types.PostureOriginOnly,
		})
	}
	return NewServer(table, nil, store.NewVRPStore(), slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
}

// chunkRecorder records the largest single write the handler makes.
type chunkRecorder struct {
	*httptest.ResponseRecorder
	largest int
}

func (c *chunkRecorder) Write(p []byte) (int, error) {
	c.largest = max(c.largest, len(p))
	return c.ResponseRecorder.Write(p)
}

// A large answer goes out in bounded writes: the handler never holds the
// whole body, whose size grows with the routes listed.
func TestRoutesStreamsLargeAnswer(t *testing.T) {
	const n = 4000
	s := largeRoutesServer(t, n)
	rec := &chunkRecorder{ResponseRecorder: httptest.NewRecorder()}
	s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil))

	var routes []RouteResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &routes); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(routes) != n {
		t.Fatalf("got %d routes, want %d", len(routes), n)
	}
	if limit := 64 << 10; rec.largest > limit {
		t.Errorf("largest write %d bytes of a %d-byte body, want at most %d", rec.largest, rec.Body.Len(), limit)
	}
}

// The body keeps the indented layout clients and docs show, and an empty
// answer is still an empty array.
func TestRoutesJSONLayout(t *testing.T) {
	for _, n := range []int{0, 1, 3} {
		s := largeRoutesServer(t, n)
		rec := httptest.NewRecorder()
		s.handleRoutes(rec, httptest.NewRequest(http.MethodGet, "/api/v1/routes", nil))
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%d routes: Content-Type %q", n, ct)
		}
		routes := []RouteResponse{}
		if err := json.Unmarshal(rec.Body.Bytes(), &routes); err != nil {
			t.Fatalf("%d routes: decode: %v", n, err)
		}
		var want bytes.Buffer
		enc := json.NewEncoder(&want)
		enc.SetIndent("", "  ")
		if err := enc.Encode(routes); err != nil {
			t.Fatal(err)
		}
		if got := rec.Body.String(); got != want.String() {
			t.Errorf("%d routes: body\n%s\nwant\n%s", n, got, want.String())
		}
	}
}
