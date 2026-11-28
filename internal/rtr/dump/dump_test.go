package dump

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func vrp(prefix string, maxLen uint8, asn uint32) types.VRP {
	return types.VRP{Prefix: netip.MustParsePrefix(prefix), MaxLength: maxLen, ASN: asn}
}

var md = Metadata{
	Generated:       time.Date(2026, 11, 24, 17, 15, 53, 0, time.UTC),
	Cache:           "rtr.example.net:3323",
	SessionID:       4242,
	Serial:          587,
	ProtocolVersion: 2,
	DataFingerprint: "00000000000000010000000000000002",
}

func TestWriteLayoutAndOrder(t *testing.T) {
	vrps := []types.VRP{
		vrp("2001:db8::/32", 48, 64500),
		vrp("192.0.2.0/24", 24, 64501),
		vrp("192.0.2.0/24", 24, 64500),
		vrp("10.0.0.0/8", 24, 64500),
		vrp("192.0.2.0/24", 24, 64500), // duplicate
		vrp("10.0.0.0/8", 8, 64500),
	}
	aspas := []types.ASPARecord{
		{CustomerASN: 64511, ProviderASNs: []uint32{3356, 0, 174, 3356}},
		{CustomerASN: 43, ProviderASNs: []uint32{293}},
	}
	var b bytes.Buffer
	if err := Write(&b, md, vrps, aspas); err != nil {
		t.Fatal(err)
	}
	want := `{
  "metadata": {
    "generated": 1795540553,
    "generatedTime": "2026-11-24T17:15:53Z",
    "cache": "rtr.example.net:3323",
    "sessionID": 4242,
    "serial": 587,
    "protocolVersion": 2,
    "dataFingerprint": "00000000000000010000000000000002",
    "aspasAvailable": true
  },
  "roas": [
    { "asn": "AS64500", "prefix": "10.0.0.0/8", "maxLength": 8 },
    { "asn": "AS64500", "prefix": "10.0.0.0/8", "maxLength": 24 },
    { "asn": "AS64500", "prefix": "192.0.2.0/24", "maxLength": 24 },
    { "asn": "AS64501", "prefix": "192.0.2.0/24", "maxLength": 24 },
    { "asn": "AS64500", "prefix": "2001:db8::/32", "maxLength": 48 }
  ],
  "aspas": [
    { "customer": "AS43", "providers": ["AS293"] },
    { "customer": "AS64511", "providers": ["AS0", "AS174", "AS3356"] }
  ]
}
`
	if got := b.String(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	var v map[string]any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
}

// Below RTR version 2 the dump has no "aspas" list: an empty one would say
// that the cache holds no ASPA.
func TestWriteNoASPAVersion(t *testing.T) {
	m := md
	m.ProtocolVersion = 1
	var b bytes.Buffer
	if err := Write(&b, m, []types.VRP{vrp("192.0.2.0/24", 24, 64500)}, nil); err != nil {
		t.Fatal(err)
	}
	var v struct {
		Metadata map[string]any   `json:"metadata"`
		ROAs     []map[string]any `json:"roas"`
		ASPAs    *[]any           `json:"aspas"`
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b.String())
	}
	if v.ASPAs != nil {
		t.Fatalf("aspas present for RTR version 1:\n%s", b.String())
	}
	if v.Metadata["aspasAvailable"] != false || !strings.Contains(v.Metadata["aspasUnavailableReason"].(string), "version 1") {
		t.Fatalf("metadata does not say ASPAs were unavailable: %v", v.Metadata)
	}
	if len(v.ROAs) != 1 {
		t.Fatalf("roas: %v", v.ROAs)
	}
}

func TestWriteEmpty(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, md, nil, nil); err != nil {
		t.Fatal(err)
	}
	var v struct {
		ROAs  []any  `json:"roas"`
		ASPAs *[]any `json:"aspas"`
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b.String())
	}
	if v.ROAs == nil || len(v.ROAs) != 0 || v.ASPAs == nil || len(*v.ASPAs) != 0 {
		t.Fatalf("want two empty lists:\n%s", b.String())
	}
}

// A customer listed twice keeps the union of its providers.
func TestSortASPAsMergesCustomer(t *testing.T) {
	got := SortASPAs([]types.ASPARecord{
		{CustomerASN: 2, ProviderASNs: []uint32{30, 10}},
		{CustomerASN: 1, ProviderASNs: []uint32{5}},
		{CustomerASN: 2, ProviderASNs: []uint32{20, 10}},
	})
	if len(got) != 2 || got[0].CustomerASN != 1 || got[1].CustomerASN != 2 {
		t.Fatalf("order: %+v", got)
	}
	if p := got[1].ProviderASNs; len(p) != 3 || p[0] != 10 || p[1] != 20 || p[2] != 30 {
		t.Fatalf("providers: %v", p)
	}
}
