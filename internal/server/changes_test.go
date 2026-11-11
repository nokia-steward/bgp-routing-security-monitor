package server

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// sameRouteIgnores are the types.Route fields (and validation-result
// fields) that sameRoute deliberately does not compare. Everything else a
// BMP announcement can change must make it report a change.
var sameRouteIgnores = map[string]bool{
	"Timestamp":       true, // when it was received
	"OwnerSession":    true, // which session owns it
	"Stale":           true, // callers treat a stale route as not there
	"ROV.MatchedVRPs": true, // detail: which VRPs matched
	"ASPA.HopDetails": true, // detail: the per-hop breakdown
}

// Every field of types.Route is either compared by sameRoute or listed in
// sameRouteIgnores: a field added to Route later fails here until it is
// decided which. For each compared field, a route differing only there is
// a change.
func TestSameRouteCoversEveryField(t *testing.T) {
	base := func() *types.Route {
		return &types.Route{
			Timestamp: time.Unix(1, 0), Router: netip.MustParseAddr("192.0.2.1"),
			PeerAddr: netip.MustParseAddr("198.18.0.1"), PeerASN: 64501,
			Prefix: netip.MustParsePrefix("203.0.113.0/24"), ASPath: []uint32{64501, 65010},
			ASPathRaw:   []types.ASSegment{{Type: types.ASSegmentSequence, ASNs: []uint32{64501, 65010}}},
			Communities: []types.Community{{High: 64501, Low: 1}}, LargeCommunities: []types.LargeCommunity{{}},
			NextHop: netip.MustParseAddr("198.18.0.1"), SecurityPosture: types.PostureOriginOnly,
			ASPA: types.ASPAResult{FailingHop: &types.ASPAHop{}},
		}
	}
	if !sameRoute(base(), base()) {
		t.Fatal("identical routes differ")
	}
	rt := reflect.TypeOf(types.Route{})
	for i := range rt.NumField() {
		f := rt.Field(i)
		if f.Type.Kind() == reflect.Struct && (f.Name == "ROV" || f.Name == "ASPA") {
			for j := range f.Type.NumField() {
				checkField(t, base, f.Name+"."+f.Type.Field(j).Name, []int{i, j})
			}
			continue
		}
		checkField(t, base, f.Name, []int{i})
	}
}

func checkField(t *testing.T, base func() *types.Route, name string, index []int) {
	t.Helper()
	if sameRouteIgnores[name] {
		return
	}
	a, b := base(), base()
	fv := reflect.ValueOf(b).Elem().FieldByIndex(index)
	if !mutate(fv) {
		t.Errorf("types.Route field %s: the test cannot vary its type %s; compare it in sameRoute or list it in sameRouteIgnores", name, fv.Type())
		return
	}
	if sameRoute(a, b) {
		t.Errorf("types.Route field %s differs but sameRoute says unchanged: compare it, or list it in sameRouteIgnores", name)
	}
}

// mutate changes v to another value of its type.
func mutate(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	case reflect.String:
		v.SetString(v.String() + "x")
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.Append(v, reflect.Zero(v.Type().Elem())))
			return true
		}
		return mutate(v.Index(0)) || func() bool { v.Set(v.Slice(0, 0)); return true }()
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
			return true
		}
		return mutate(v.Elem())
	case reflect.Struct:
		switch x := v.Interface().(type) {
		case netip.Addr:
			v.Set(reflect.ValueOf(x.Next()))
			return true
		case netip.Prefix:
			v.Set(reflect.ValueOf(netip.PrefixFrom(x.Addr().Next(), x.Bits())))
			return true
		case time.Time:
			v.Set(reflect.ValueOf(x.Add(time.Second)))
			return true
		}
		for i := range v.NumField() {
			if v.Field(i).CanSet() && mutate(v.Field(i)) {
				return true
			}
		}
		return false
	default:
		return false
	}
	return true
}
