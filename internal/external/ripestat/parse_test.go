package ripestat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/external"
)

// fixture reads a recorded RIPEstat looking-glass response from testdata.
// Nothing in this package's tests reaches the real API.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

// ─── TestSummarize ───

func TestSummarize(t *testing.T) {
	tests := []struct {
		name           string
		fixture        string
		wantOrigins    []external.GlobalOriginObservation
		wantCollectors int
	}{
		{
			// Real recorded 8.8.8.0/24 response, trimmed to 3 collectors
			// with 3 peers each. Every peer agrees on AS15169.
			name:    "single origin across collectors",
			fixture: "looking-glass-match.json",
			wantOrigins: []external.GlobalOriginObservation{
				{ASN: 15169, CollectorCount: 9},
			},
			wantCollectors: 9,
		},
		{
			// MOAS: AS64511 seen by 3 collector peers, AS65000 by 2.
			name:    "MOAS sorted most-observed first",
			fixture: "looking-glass-moas.json",
			wantOrigins: []external.GlobalOriginObservation{
				{ASN: 64511, CollectorCount: 3},
				{ASN: 65000, CollectorCount: 2},
			},
			wantCollectors: 5,
		},
		{
			// Exact-match call with no collector carrying the prefix.
			name:           "no observations",
			fixture:        "looking-glass-empty.json",
			wantOrigins:    []external.GlobalOriginObservation{},
			wantCollectors: 0,
		},
		{
			// Duplicate collector peer counted once; absent asn_origin
			// resolved from as_path; AS_SET, empty and AS0 origins skipped.
			// Leaves RRC00|.1, RRC00|.2 and RRC01|.1 for AS64511.
			name:    "odd origin encodings",
			fixture: "looking-glass-odd-origins.json",
			wantOrigins: []external.GlobalOriginObservation{
				{ASN: 64511, CollectorCount: 3},
			},
			wantCollectors: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := summarize(fixture(t, tt.fixture))
			if err != nil {
				t.Fatalf("summarize: unexpected error: %v", err)
			}
			if got.CollectorCount != tt.wantCollectors {
				t.Errorf("CollectorCount = %d, want %d", got.CollectorCount, tt.wantCollectors)
			}
			if len(got.Origins) != len(tt.wantOrigins) {
				t.Fatalf("Origins = %+v, want %+v", got.Origins, tt.wantOrigins)
			}
			for i, want := range tt.wantOrigins {
				if got.Origins[i] != want {
					t.Errorf("Origins[%d] = %+v, want %+v", i, got.Origins[i], want)
				}
			}
		})
	}
}

// ─── TestSummarizeMalformed ───

// Malformed input must produce an error, never a panic and never a silently
// empty summary that would be mistaken for LocalOnly.
func TestSummarizeMalformed(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
	}{
		{"truncated json", "looking-glass-truncated.json"},
		{"missing data object", "looking-glass-missing-data.json"},
		{"data call error status", "looking-glass-error-status.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := summarize(fixture(t, tt.fixture)); err == nil {
				t.Fatal("summarize: want error, got nil")
			}
		})
	}
}

func TestSummarizeEmptyBody(t *testing.T) {
	if _, err := summarize(nil); err == nil {
		t.Fatal("summarize(nil): want error, got nil")
	}
	if _, err := summarize([]byte("null")); err == nil {
		t.Fatal(`summarize("null"): want error, got nil`)
	}
}

// ─── TestParseASN ───

func TestParseASN(t *testing.T) {
	tests := []struct {
		in      string
		want    uint32
		wantOK  bool
		comment string
	}{
		{"15169", 15169, true, "plain"},
		{" 64511 ", 64511, true, "surrounding whitespace"},
		{"4294967294", 4294967294, true, "32-bit ASN"},
		{"", 0, false, "empty"},
		{"0", 0, false, "AS0 is reserved, not a usable origin"},
		{"{64500,64501}", 0, false, "AS_SET is ambiguous"},
		{"64500,64501", 0, false, "comma-separated set"},
		{"AS15169", 0, false, "non-numeric prefix"},
		{"4294967296", 0, false, "overflows uint32"},
		{"-1", 0, false, "negative"},
	}

	for _, tt := range tests {
		t.Run(tt.comment, func(t *testing.T) {
			got, ok := parseASN(tt.in)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseASN(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// ─── TestOriginASN ───

func TestOriginASN(t *testing.T) {
	tests := []struct {
		name   string
		peer   lookingGlassPeer
		want   uint32
		wantOK bool
	}{
		{
			name:   "explicit asn_origin wins",
			peer:   lookingGlassPeer{ASNOrigin: "64511", ASPath: "34854 6939 64511"},
			want:   64511,
			wantOK: true,
		},
		{
			name:   "absent asn_origin falls back to last as_path hop",
			peer:   lookingGlassPeer{ASPath: "34854 6939 64511"},
			want:   64511,
			wantOK: true,
		},
		{
			// The last as_path hop is the same AS_SET, and walking further
			// back would wrongly credit transit AS6939 as the origin.
			name:   "AS_SET origin is not resolved from as_path",
			peer:   lookingGlassPeer{ASNOrigin: "{64500,64501}", ASPath: "34854 6939 {64500,64501}"},
			wantOK: false,
		},
		{
			name:   "no origin information",
			peer:   lookingGlassPeer{},
			wantOK: false,
		},
		{
			name:   "as_path ending in an AS_SET",
			peer:   lookingGlassPeer{ASPath: "34854 6939 {64500,64501}"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := originASN(tt.peer)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("originASN = (%d, %v), want (%d, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
