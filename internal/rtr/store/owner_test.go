package store

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// #66: the VRP store holds each distinct VRP once. An owner announcing what
// it already holds is a duplicate (AddVRPFrom false) that adds to its count;
// a withdrawal takes 1 from it, and one of a VRP the owner does not hold is
// unknown and changes nothing. The same VRP from two owners counts once in
// Count and once in each OwnerCount; a VRP leaves the set when its last
// owner releases it; and ClearOwner and ReplaceOwner change one owner's VRPs
// (and the Unowned, restored ones) only.
func TestVRPStoreOwners(t *testing.T) {
	v := func(p string, asn uint32) types.VRP {
		return types.VRP{Prefix: netip.MustParsePrefix(p), MaxLength: 24, ASN: asn}
	}
	shared, onlyA, restored := v("192.0.2.0/24", 1), v("198.51.100.0/24", 2), v("203.0.113.0/24", 3)
	s := NewVRPStore()
	s.ReplaceAll([]types.VRP{restored, restored}, 0, 0)
	if s.Count() != 1 {
		t.Fatalf("ReplaceAll of a VRP listed twice: Count %d, want 1", s.Count())
	}
	a, _ := s.NewOwner()
	b, _ := s.NewOwner()
	if a == b || a == Unowned || b == Unowned {
		t.Fatalf("owners %d and %d, want two distinct non-Unowned", a, b)
	}
	if !s.AddVRPFrom(a, shared) || !s.AddVRPFrom(a, onlyA) || !s.AddVRPFrom(b, shared) {
		t.Fatal("first announcements reported as duplicates")
	}
	if s.AddVRPFrom(a, shared) {
		t.Error("A announcing shared again: not reported as a duplicate")
	}
	if s.Count() != 3 || s.OwnerCount(a) != 2 || s.OwnerCount(b) != 1 {
		t.Errorf("Count %d A %d B %d, want 3, 2, 1", s.Count(), s.OwnerCount(a), s.OwnerCount(b))
	}
	s.RebuildIndex()
	if got := s.FindCovering(shared.Prefix); !slices.Equal(got, []types.VRP{shared}) {
		t.Errorf("FindCovering = %v, want shared once", got)
	}

	// A announced shared twice: its count is 2, so one withdrawal leaves it
	// held (the Fort 1.7.0 pattern), the second releases it, a third is
	// unknown.
	for i, want := range [][2]bool{{true, false}, {true, true}, {false, false}} {
		if known, released := s.RemoveVRPFrom(a, shared); known != want[0] || released != want[1] {
			t.Errorf("withdrawal %d of shared by A: known %v released %v, want %v %v", i+1, known, released, want[0], want[1])
		}
	}
	if s.Count() != 3 || s.OwnerCount(a) != 1 {
		t.Errorf("after A withdrew shared, Count %d A %d, want 3 (B holds it) and 1", s.Count(), s.OwnerCount(a))
	}
	s.ClearOwner(a)
	if got := s.All(); !slices.Equal(got, []types.VRP{shared}) || s.OwnerCount(b) != 1 || s.OwnerCount(a) != 0 {
		t.Errorf("after ClearOwner(A): %v (A %d, B %d), want only B's shared", got, s.OwnerCount(a), s.OwnerCount(b))
	}

	// A full sync built aside replaces A's VRPs at once; a VRP announced
	// twice in it keeps its count.
	g := NewVRPStage()
	if !g.Announce(onlyA) || g.Announce(onlyA) || !g.Announce(restored) || !g.Withdraw(restored) || g.Withdraw(restored) {
		t.Fatal("stage: wrong added/known results")
	}
	s.ReplaceOwner(a, g)
	if got := s.All(); len(got) != 2 || !slices.Contains(got, onlyA) || !slices.Contains(got, shared) || s.OwnerCount(a) != 1 {
		t.Errorf("after ReplaceOwner(A): %v (A %d), want B's shared and A's onlyA", got, s.OwnerCount(a))
	}
	if known, released := s.RemoveVRPFrom(a, onlyA); !known || released {
		t.Errorf("onlyA staged twice, withdrawn once: known %v released %v, want held still", known, released)
	}
}

// The ASPA store keeps one record per owner and customer: an announcement
// replaces the owner's provider set, a withdrawal removes it, and lookups
// see the union of the owners' sets.
func TestASPAStoreOwners(t *testing.T) {
	s := NewASPAStore()
	const a, b Owner = 1, 2
	if changed, replaced := s.Announce(a, 64500, []uint32{2, 1}); !changed || replaced {
		t.Errorf("first announcement: changed %v replaced %v, want true false", changed, replaced)
	}
	if changed, replaced := s.Announce(a, 64500, []uint32{1, 2}); changed || !replaced {
		t.Errorf("same set again: changed %v replaced %v, want false true", changed, replaced)
	}
	s.Announce(b, 64500, []uint32{3})
	if !s.HasProvider(64500, 1) || !s.HasProvider(64500, 3) || s.Count() != 1 || s.OwnerCount(a) != 1 {
		t.Errorf("union of A and B not seen: %+v", s.GetRecord(64500))
	}
	if changed, _ := s.Announce(a, 64500, []uint32{1}); !changed || s.HasProvider(64500, 2) {
		t.Errorf("A's replacement without 2: changed %v, record %+v", changed, s.GetRecord(64500))
	}
	if changed, known := s.Withdraw(a, 64500); !changed || !known {
		t.Errorf("withdraw: changed %v known %v", changed, known)
	}
	if s.HasProvider(64500, 1) || !s.HasProvider(64500, 3) {
		t.Errorf("after A's withdrawal: %+v, want B's {3}", s.GetRecord(64500))
	}
	if _, known := s.Withdraw(a, 64500); known {
		t.Error("withdrawing again: known")
	}
	s.ClearOwner(b)
	if s.Count() != 0 {
		t.Errorf("after ClearOwner(B), Count %d, want 0", s.Count())
	}
}
