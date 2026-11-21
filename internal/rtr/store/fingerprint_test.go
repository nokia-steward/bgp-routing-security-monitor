package store

import (
	"net/netip"
	"testing"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

func fpVRP(s string, maxLen uint8, asn uint32) types.VRP {
	return types.VRP{Prefix: netip.MustParsePrefix(s), MaxLength: maxLen, ASN: asn}
}

// An owner's fingerprint depends on its set only: the order records came in,
// a full sync's ReplaceOwner or an incremental's adds and removes, another
// owner's records and duplicate announcements change nothing.
func TestOwnerFingerprintIsTheSet(t *testing.T) {
	a, b, c := fpVRP("10.0.0.0/24", 24, 65001), fpVRP("2001:db8::/32", 48, 65002), fpVRP("10.0.0.0/24", 25, 65001)
	s := NewVRPStore()
	o1, _ := s.NewOwner()
	o2, _ := s.NewOwner()
	empty := s.OwnerFingerprint(o1)

	s.AddVRPFrom(o1, a)
	s.AddVRPFrom(o1, b)
	s.AddVRPFrom(o1, a) // a duplicate announcement: still held once
	s.AddVRPFrom(o2, c)
	ab := s.OwnerFingerprint(o1)

	stage := NewVRPStage()
	stage.Announce(b)
	stage.Announce(a)
	s.ReplaceOwner(o2, stage)
	if got := s.OwnerFingerprint(o2); got != ab {
		t.Errorf("{b, a} by ReplaceOwner %v, {a, b} by adds %v", got, ab)
	}
	if ab == empty {
		t.Fatal("fingerprint of {a, b} is the empty set's")
	}

	s.AddVRPFrom(o1, c)
	if s.OwnerFingerprint(o1) == ab {
		t.Error("adding c changed nothing")
	}
	s.RemoveVRPFrom(o1, c)
	if s.OwnerFingerprint(o1) != ab {
		t.Error("removing c again did not return to {a, b}")
	}
	s.RemoveVRPFrom(o1, a) // the duplicate's count
	if s.OwnerFingerprint(o1) != ab {
		t.Error("withdrawing a duplicate changed the set")
	}
	s.RemoveVRPFrom(o1, a)
	s.RemoveVRPFrom(o1, b)
	if s.OwnerFingerprint(o1) != empty {
		t.Error("an emptied owner's fingerprint is not the empty set's")
	}
	s.ClearOwner(o2)
	if s.OwnerFingerprint(o2) != empty {
		t.Error("a cleared owner's fingerprint is not the empty set's")
	}
	// A VRP's maxLength and address family are part of it.
	if VRPHash(a) == VRPHash(c) || VRPHash(fpVRP("0.0.0.0/0", 0, 1)) == VRPHash(fpVRP("::/0", 0, 1)) {
		t.Error("distinct VRPs hash alike")
	}
}

// An ASPA owner's fingerprint follows provider-set replacements.
func TestASPAOwnerFingerprint(t *testing.T) {
	s := NewASPAStore()
	const o Owner = 1
	empty := s.OwnerFingerprint(o)
	s.Announce(o, 64500, []uint32{2, 1})
	one := s.OwnerFingerprint(o)
	s.Announce(o, 64500, []uint32{1, 3}) // replaces the provider set
	if s.OwnerFingerprint(o) == one {
		t.Error("a provider-set replacement changed nothing")
	}
	s.Announce(o, 64500, []uint32{1, 2, 2})
	if s.OwnerFingerprint(o) != one {
		t.Error("back to providers {1, 2}: not the same fingerprint")
	}
	stage := NewASPAStage()
	stage.Announce(64500, []uint32{2, 1})
	const o2 Owner = 2
	s.ReplaceOwner(o2, stage)
	if s.OwnerFingerprint(o2) != one {
		t.Error("the same record by ReplaceOwner: another fingerprint")
	}
	s.Withdraw(o, 64500)
	if s.OwnerFingerprint(o) != empty {
		t.Error("withdrawn: not the empty set's fingerprint")
	}
	if ASPAHash(1, []uint32{2}) == VRPHash(fpVRP("0.0.0.1/32", 32, 2)) {
		t.Error("an ASPA record and a VRP hash alike")
	}
}
