package types

import (
	"testing"
	"unsafe"
)

// The reason code must not grow ROVResult, and with it every Route: the
// table holds millions. Code sits in the padding after State. On 64-bit:
// State and Code (1+1, padded to 8), the MatchedVRPs slice header (24) and
// the Reason string header (16).
func TestROVResultSize(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("sizes below are for 64-bit platforms")
	}
	if got := unsafe.Sizeof(ROVResult{}); got != 48 {
		t.Errorf("ROVResult is %d bytes, want 48: the reason code must not add to each route", got)
	}
}

func TestCommunityStrings(t *testing.T) {
	if got := CommunityBlackhole.String(); got != "65535:666" {
		t.Errorf("BLACKHOLE = %q, want 65535:666", got)
	}
	if got := (LargeCommunity{GlobalAdmin: 6695, LocalData1: 1911, LocalData2: 172}).String(); got != "6695:1911:172" {
		t.Errorf("large community = %q, want 6695:1911:172", got)
	}
	r := Route{Communities: []Community{{High: 6695, Low: 1}, CommunityBlackhole}}
	if !r.HasCommunity(CommunityBlackhole) || r.HasCommunity(Community{High: 65535, Low: 667}) {
		t.Errorf("HasCommunity wrong for %v", r.Communities)
	}
}
