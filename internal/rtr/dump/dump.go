// Package dump writes the VRPs and ASPAs an RTR cache served in the layout
// of Routinator's "json" output format, so that two dumps, or a dump and a
// validator's export, can be compared with a plain diff.
//
// RTR does not carry the trust anchor of a record, so the "ta" member of
// Routinator's records is left out; a validator's "jsonext" export gives the
// trust anchor and the repository of each record.
package dump

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// Metadata describes where and when the records were read.
type Metadata struct {
	// Generated is when the snapshot was taken.
	Generated time.Time
	// Cache is the address of the RTR cache (host:port).
	Cache string
	// SessionID, Serial and ProtocolVersion are the cache's at the End of
	// Data of the snapshot.
	SessionID       uint16
	Serial          uint32
	ProtocolVersion uint8
	// DataFingerprint is the fingerprint of the records (see
	// store.Fingerprint), as the telemetry's data_fingerprint writes it.
	DataFingerprint string
}

// ASPAAvailable reports whether the session's protocol version carries
// ASPA records (version 2 and later).
func (m Metadata) ASPAAvailable() bool { return m.ProtocolVersion >= 2 }

// Write writes the records to w; it sorts vrps in place. VRPs are sorted by address family (IPv4
// first), address, prefix length, maximum length and AS number; ASPAs by
// customer AS, each with its providers sorted. Duplicates are dropped. When
// the session's version carries no ASPA, the "aspas" member is left out and
// the metadata says so, rather than writing an empty list that would read as
// "this cache holds no ASPA".
func Write(w io.Writer, md Metadata, vrps []types.VRP, aspas []types.ASPARecord) error {
	bw := bufio.NewWriterSize(w, 1<<20)
	vrps = SortVRPs(vrps)

	gen := md.Generated.UTC()
	fmt.Fprintf(bw, "{\n  \"metadata\": {\n")
	fmt.Fprintf(bw, "    \"generated\": %d,\n", gen.Unix())
	fmt.Fprintf(bw, "    \"generatedTime\": %q,\n", gen.Format(time.RFC3339))
	fmt.Fprintf(bw, "    \"cache\": %q,\n", md.Cache)
	fmt.Fprintf(bw, "    \"sessionID\": %d,\n", md.SessionID)
	fmt.Fprintf(bw, "    \"serial\": %d,\n", md.Serial)
	fmt.Fprintf(bw, "    \"protocolVersion\": %d,\n", md.ProtocolVersion)
	fmt.Fprintf(bw, "    \"dataFingerprint\": %q,\n", md.DataFingerprint)
	if md.ASPAAvailable() {
		fmt.Fprintf(bw, "    \"aspasAvailable\": true\n")
	} else {
		fmt.Fprintf(bw, "    \"aspasAvailable\": false,\n")
		fmt.Fprintf(bw, "    \"aspasUnavailableReason\": %q\n",
			fmt.Sprintf("RTR version %d does not carry ASPA records", md.ProtocolVersion))
	}
	fmt.Fprintf(bw, "  },\n")

	writeList(bw, "roas", len(vrps), !md.ASPAAvailable(), func(i int) string {
		v := vrps[i]
		return fmt.Sprintf(`{ "asn": "AS%d", "prefix": "%s", "maxLength": %d }`, v.ASN, v.Prefix, v.MaxLength)
	})
	if md.ASPAAvailable() {
		recs := SortASPAs(aspas)
		writeList(bw, "aspas", len(recs), true, func(i int) string {
			r := recs[i]
			b := make([]byte, 0, 32+12*len(r.ProviderASNs))
			b = fmt.Appendf(b, `{ "customer": "AS%d", "providers": [`, r.CustomerASN)
			for j, p := range r.ProviderASNs {
				if j > 0 {
					b = append(b, ", "...)
				}
				b = fmt.Appendf(b, `"AS%d"`, p)
			}
			b = append(b, "] }"...)
			return string(b)
		})
	}
	fmt.Fprintf(bw, "}\n")
	return bw.Flush()
}

// writeList writes one member holding a list, one record a line.
func writeList(w *bufio.Writer, name string, n int, last bool, item func(int) string) {
	end := ","
	if last {
		end = ""
	}
	if n == 0 {
		fmt.Fprintf(w, "  %q: []%s\n", name, end)
		return
	}
	fmt.Fprintf(w, "  %q: [\n", name)
	for i := range n {
		sep := ","
		if i == n-1 {
			sep = ""
		}
		fmt.Fprintf(w, "    %s%s\n", item(i), sep)
	}
	fmt.Fprintf(w, "  ]%s\n", end)
}

// compareVRP orders VRPs as Write writes them.
func compareVRP(a, b types.VRP) int {
	pa, pb := a.Prefix.Addr(), b.Prefix.Addr()
	if a4, b4 := pa.Is4(), pb.Is4(); a4 != b4 {
		if a4 {
			return -1
		}
		return 1
	}
	if c := pa.Compare(pb); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.MaxLength, b.MaxLength); c != 0 {
		return c
	}
	return cmp.Compare(a.ASN, b.ASN)
}

// SortVRPs returns the VRPs sorted as Write writes them, without duplicates.
// It sorts vrps in place.
func SortVRPs(vrps []types.VRP) []types.VRP {
	slices.SortFunc(vrps, compareVRP)
	return slices.CompactFunc(vrps, func(a, b types.VRP) bool { return compareVRP(a, b) == 0 })
}

// SortASPAs returns copies of the records sorted by customer AS, each with
// its providers sorted and without duplicates. A customer that appears more
// than once keeps the union of its providers.
func SortASPAs(aspas []types.ASPARecord) []types.ASPARecord {
	byCustomer := make(map[uint32][]uint32, len(aspas))
	for _, r := range aspas {
		byCustomer[r.CustomerASN] = append(byCustomer[r.CustomerASN], r.ProviderASNs...)
	}
	out := make([]types.ASPARecord, 0, len(byCustomer))
	for c, ps := range byCustomer {
		ps = slices.Clone(ps)
		slices.Sort(ps)
		out = append(out, types.ASPARecord{CustomerASN: c, ProviderASNs: slices.Compact(ps)})
	}
	slices.SortFunc(out, func(a, b types.ASPARecord) int { return cmp.Compare(a.CustomerASN, b.CustomerASN) })
	return out
}
