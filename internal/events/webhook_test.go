package events

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func makeWebhookEvent() Event {
	return Event{
		ID:        NewID(),
		Timestamp: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		Type:      EventTypePostureChange,
		Route: &types.Route{
			Prefix:   netip.MustParsePrefix("10.0.0.0/8"),
			PeerAddr: netip.MustParseAddr("192.0.2.1"),
			PeerASN:  65001,
			ROV:      types.ROVResult{State: types.ROVValid},
			ASPA:     types.ASPAResult{State: types.ASPAInvalid},
		},
		OldPosture: types.PostureUnverified,
		NewPosture: types.PostureOriginInvalid,
		RouterID:   "router1",
	}
}

// fastWebhookAction creates a WebhookAction with a very short initial backoff
// so retry tests complete quickly.
func fastWebhookAction(rawURL string) *WebhookAction {
	a := newWebhookAction(rawURL, "", "", 3, 5*time.Second, nil, slog.Default())
	a.initialBackoff = time.Millisecond
	return a
}

func TestWebhookAction_Success(t *testing.T) {
	event := makeWebhookEvent()
	var got webhookPayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("unmarshal payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := fastWebhookAction(srv.URL)
	if err := a.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got.ID != event.ID {
		t.Errorf("id: got %q, want %q", got.ID, event.ID)
	}
	wantTS := event.Timestamp.Format(time.RFC3339Nano)
	if got.Timestamp != wantTS {
		t.Errorf("timestamp: got %q, want %q", got.Timestamp, wantTS)
	}
	if got.Type != string(event.Type) {
		t.Errorf("type: got %q, want %q", got.Type, event.Type)
	}
	if got.RouterID != event.RouterID {
		t.Errorf("router_id: got %q, want %q", got.RouterID, event.RouterID)
	}
	if got.Prefix != event.Route.Prefix.String() {
		t.Errorf("prefix: got %q, want %q", got.Prefix, event.Route.Prefix.String())
	}
	if got.PeerAddr != event.Route.PeerAddr.String() {
		t.Errorf("peer_addr: got %q, want %q", got.PeerAddr, event.Route.PeerAddr.String())
	}
	if got.PeerASN != event.Route.PeerASN {
		t.Errorf("peer_asn: got %d, want %d", got.PeerASN, event.Route.PeerASN)
	}
	if got.OldPosture != string(event.OldPosture) {
		t.Errorf("old_posture: got %q, want %q", got.OldPosture, event.OldPosture)
	}
	if got.NewPosture != string(event.NewPosture) {
		t.Errorf("new_posture: got %q, want %q", got.NewPosture, event.NewPosture)
	}
	if got.ROVState != event.Route.ROV.State.String() {
		t.Errorf("rov_state: got %q, want %q", got.ROVState, event.Route.ROV.State.String())
	}
	if got.ASPAState != event.Route.ASPA.State.String() {
		t.Errorf("aspa_state: got %q, want %q", got.ASPAState, event.Route.ASPA.State.String())
	}
}

func TestWebhookAction_Retry(t *testing.T) {
	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n := requests.Add(1); n <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := fastWebhookAction(srv.URL)
	if err := a.Execute(context.Background(), makeWebhookEvent()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := requests.Load(); n != 3 {
		t.Errorf("expected 3 requests, got %d", n)
	}
}

func TestWebhookAction_NoRetryOn400(t *testing.T) {
	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	a := fastWebhookAction(srv.URL)
	if err := a.Execute(context.Background(), makeWebhookEvent()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("expected 1 request (no retry on 400), got %d", n)
	}
}

func TestWebhookAction_HMACSignature(t *testing.T) {
	const secret = "test-secret-key"
	event := makeWebhookEvent()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

		if got := r.Header.Get("X-RAVEN-Signature"); got != expected {
			t.Errorf("X-RAVEN-Signature: got %q, want %q", got, expected)
		}

		// Verify the signed body parses back correctly.
		var p webhookPayload
		if err := json.NewDecoder(bytes.NewReader(body)).Decode(&p); err != nil {
			t.Errorf("decode signed body: %v", err)
		}
		if p.ID != event.ID {
			t.Errorf("id mismatch after signing: got %q, want %q", p.ID, event.ID)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newWebhookAction(srv.URL, secret, "", 1, 5*time.Second, nil, slog.Default())
	if err := a.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestWebhookAction_DeadLetter(t *testing.T) {
	var requests atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	a := fastWebhookAction(srv.URL)
	// Execute must return nil (dead-lettered, not propagated) even when all
	// attempts are exhausted.
	if err := a.Execute(context.Background(), makeWebhookEvent()); err != nil {
		t.Fatalf("Execute returned error after dead-letter: %v", err)
	}
	if n := requests.Load(); n != 3 {
		t.Errorf("expected 3 attempts, got %d", n)
	}
}

func TestWebhookPayloadNewFields(t *testing.T) {
	vrp := types.VRP{
		Prefix:    netip.MustParsePrefix("10.0.0.0/24"),
		ASN:       3215,
		MaxLength: 24,
	}
	event := Event{
		ID:        NewID(),
		Timestamp: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		Type:      EventTypePostureChange,
		Route: &types.Route{
			Prefix:   netip.MustParsePrefix("10.0.0.0/24"),
			PeerAddr: netip.MustParseAddr("192.0.2.1"),
			PeerASN:  65001,
			ASPath:   []uint32{65001, 64001},
			ROV: types.ROVResult{
				State:       types.ROVInvalid,
				MatchedVRPs: []types.VRP{vrp},
			},
			ASPA: types.ASPAResult{State: types.ASPAUnknown},
		},
		OldPosture: types.PostureSecured,
		NewPosture: types.PostureOriginInvalid,
	}

	var got webhookPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newWebhookAction(srv.URL, "", "alert-our-prefix-hijacked", 1, 5*time.Second, nil, slog.Default())
	if err := a.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got.RuleName != "alert-our-prefix-hijacked" {
		t.Errorf("rule_name: got %q, want %q", got.RuleName, "alert-our-prefix-hijacked")
	}
	if got.OriginASN != 64001 {
		t.Errorf("origin_asn: got %d, want 64001", got.OriginASN)
	}
	if len(got.ProtectedASNs) != 1 || got.ProtectedASNs[0] != 3215 {
		t.Errorf("protected_asns: got %v, want [3215]", got.ProtectedASNs)
	}
}

func TestWebhookPayloadProtectedASNsOmittedWhenEmpty(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := newWebhookAction(srv.URL, "", "my-rule", 1, 5*time.Second, nil, slog.Default())
	if err := a.Execute(context.Background(), makeWebhookEvent()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if bytes.Contains(body, []byte("protected_asns")) {
		t.Errorf("expected protected_asns to be omitted from JSON, but it was present")
	}
}
