package rtrtest

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// VRP is one Validated ROA Payload a Server serves.
type VRP struct {
	Prefix netip.Prefix
	MaxLen uint8
	ASN    uint32
}

// ASPASet is one customer AS's provider set. A Server sends ASPAs only to
// clients at version 2.
type ASPASet struct {
	Customer  uint32
	Providers []uint32
}

// Delta is a change to a Server's data set: one serial step.
type Delta struct {
	AnnounceVRPs  []VRP
	WithdrawVRPs  []VRP
	AnnounceASPAs []ASPASet // replaces the customer's provider set
	WithdrawASPAs []uint32  // customer ASNs
}

// GenVRPs returns n distinct IPv4 VRPs, /24s numbered from first, each
// originated by asn. Use different first values for disjoint sets.
func GenVRPs(first, n int, asn uint32) []VRP {
	out := make([]VRP, n)
	for i := range out {
		k := first + i
		addr := netip.AddrFrom4([4]byte{10, byte(k >> 16), byte(k >> 8), byte(k)})
		out[i] = VRP{Prefix: netip.PrefixFrom(addr, 24), MaxLen: 24, ASN: asn}
	}
	return out
}

// Action is what a Server does with one query.
type Action struct {
	kind     actionKind
	code     uint16
	keepOpen bool
}

type actionKind int

const (
	actUnset actionKind = iota // the zero Action: use the default
	actAnswer
	actError
	actFIN
	actRST
	actStall
)

func (a Action) String() string {
	switch a.kind {
	case actAnswer:
		return "answer"
	case actError:
		return fmt.Sprintf("error report code %d (keep open %t)", a.code, a.keepOpen)
	case actFIN:
		return "close (FIN)"
	case actRST:
		return "reset (RST)"
	default:
		return "stall"
	}
}

var (
	// Answer answers the query from the data set: the default for a query
	// at a supported version.
	Answer = Action{kind: actAnswer}
	// CloseFIN closes the connection cleanly without answering.
	CloseFIN = Action{kind: actFIN}
	// CloseRST resets the connection without answering.
	CloseRST = Action{kind: actRST}
	// Stall answers nothing and leaves the connection open: a cache that
	// accepted and hung.
	Stall = Action{kind: actStall}
)

// ReportError answers with an Error Report carrying code and then closes
// the connection (FIN), as caches do.
func ReportError(code uint16) Action { return Action{kind: actError, code: code} }

// ReportErrorKeepOpen answers with an Error Report and leaves the connection
// open; the client is expected to close it.
func ReportErrorKeepOpen(code uint16) Action {
	return Action{kind: actError, code: code, keepOpen: true}
}

// Error Report codes (RFC 8210 §12) the tests use.
const (
	CodeNoDataAvailable    uint16 = 2
	CodeUnsupportedVersion uint16 = 4
)

// ServerConfig sets how a Server behaves.
type ServerConfig struct {
	// MaxVersion is the highest RTR version the cache speaks: 0, 1 or 2.
	// It answers a query at a lower version at that version.
	MaxVersion uint8
	// Unsupported is what the cache does with a query above MaxVersion.
	// Unset, it is ReportError(4): an Error Report code 4, then close.
	// Answer makes it answer at MaxVersion.
	Unsupported Action
	// ErrorAtQueryVersion makes an Error Report carry the query's version
	// rather than MaxVersion. Caches differ; RFC 8210 §7 asks for the
	// cache's own.
	ErrorAtQueryVersion bool
	// Session is the cache's session ID; Refresh, Retry and Expire its End
	// of Data intervals (seconds; zero values are sent as such).
	Session                uint16
	Refresh, Retry, Expire uint32
}

// Server is a fake RTR cache that answers queries on its own from a VRP and
// ASPA data set, which the test can change serial by serial and announce with
// Serial Notify. A test scripts failures with Then, and asserts on what the
// client sent with NextQuery and Received.
type Server struct {
	*Cache
	t   testing.TB
	cfg ServerConfig

	queries chan Query // copy of every query, for NextQuery

	mu       sync.Mutex
	serial   uint32
	vrps     map[VRP]bool
	aspas    map[uint32][]uint32
	history  map[uint32]step // the change that produced each serial
	script   []Action
	received []Query
	sessions []*sessionConn // connections answered with a Cache Response, latest last
}

type sessionConn struct {
	conn    *Conn
	version uint8
}

// NewServer starts a fake cache with an empty data set at serial 0. It is
// closed when the test ends.
func NewServer(t testing.TB, cfg ServerConfig) *Server {
	t.Helper()
	if cfg.MaxVersion > 2 {
		t.Fatalf("rtrtest: MaxVersion %d: only 0, 1 and 2 exist", cfg.MaxVersion)
	}
	if cfg.Unsupported == (Action{}) {
		cfg.Unsupported = ReportError(CodeUnsupportedVersion)
	}
	s := &Server{
		Cache:   NewCache(t),
		t:       t,
		cfg:     cfg,
		queries: make(chan Query, 4096),
		vrps:    map[VRP]bool{},
		aspas:   map[uint32][]uint32{},
		history: map[uint32]step{},
	}
	go s.loop()
	return s
}

// SetData replaces the data set without a serial change, for use before
// the client connects.
func (s *Server) SetData(vrps []VRP, aspas []ASPASet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vrps = map[VRP]bool{}
	for _, v := range vrps {
		s.vrps[v] = true
	}
	s.aspas = map[uint32][]uint32{}
	for _, a := range aspas {
		s.aspas[a.Customer] = slices.Clone(a.Providers)
	}
}

// Advance applies d as the next serial and returns it. Clients learn of it
// when they next poll, or at once with Notify.
func (s *Server) Advance(d Delta) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range d.AnnounceVRPs {
		s.vrps[v] = true
	}
	for _, v := range d.WithdrawVRPs {
		delete(s.vrps, v)
	}
	for _, a := range d.AnnounceASPAs {
		s.aspas[a.Customer] = slices.Clone(a.Providers)
	}
	// A withdrawal names the providers it removes: the client removes
	// exactly those.
	st := step{
		announceVRPs:  slices.Clone(d.AnnounceVRPs),
		withdrawVRPs:  slices.Clone(d.WithdrawVRPs),
		announceASPAs: slices.Clone(d.AnnounceASPAs),
	}
	for _, c := range d.WithdrawASPAs {
		st.withdrawASPAs = append(st.withdrawASPAs, ASPASet{Customer: c, Providers: s.aspas[c]})
		delete(s.aspas, c)
	}
	s.serial++
	s.history[s.serial] = st
	return s.serial
}

// step is one serial's change as the cache sends it.
type step struct {
	announceVRPs, withdrawVRPs   []VRP
	announceASPAs, withdrawASPAs []ASPASet
}

// Serial is the cache's current serial.
func (s *Server) Serial() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serial
}

// Counts is the size of the data set: VRPs and ASPA customers.
func (s *Server) Counts() (vrps, aspas int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.vrps), len(s.aspas)
}

// Notify sends a Serial Notify for the current serial on the latest session
// (the latest connection answered with a Cache Response). It fails the test
// if there is none.
func (s *Server) Notify() {
	s.t.Helper()
	sc := s.latest()
	s.mu.Lock()
	serial := s.serial
	s.mu.Unlock()
	sc.conn.Send(SerialNotify(sc.version, s.cfg.Session, serial))
}

// Session returns the latest session's connection, to close or reset it
// mid-session. It fails the test if there is none.
func (s *Server) Session() *Conn {
	s.t.Helper()
	return s.latest().conn
}

// Sessions is how many connections the cache has answered with a Cache
// Response.
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

func (s *Server) latest() *sessionConn {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) == 0 {
		s.t.Fatal("rtrtest: no session yet")
	}
	return s.sessions[len(s.sessions)-1]
}

// Then queues actions for the next queries, one each, in order, in place of
// the default. A queued action applies whatever the query's version.
func (s *Server) Then(actions ...Action) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.script = append(s.script, actions...)
}

// Received returns every query the client has sent, in order.
func (s *Server) Received() []Query {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.received)
}

// NextQuery returns the next query the cache received (after the Server
// has acted on it), failing the test if none arrives within timeout.
func (s *Server) NextQuery(timeout time.Duration) Query {
	s.t.Helper()
	select {
	case q := <-s.queries:
		return q
	case <-time.After(timeout):
		s.t.Fatalf("rtrtest: no query within %v", timeout)
		return Query{}
	}
}

// NoQuery fails the test if a query arrives within d (from now: queries
// received before, read with NextQuery or not, do not count).
func (s *Server) NoQuery(d time.Duration, why string) {
	s.t.Helper()
	before := len(s.Received())
	time.Sleep(d)
	if got := s.Received(); len(got) > before {
		q := got[before]
		s.t.Fatalf("rtrtest: unexpected query (type %d, version %d, serial %d) %s", q.Type, q.Version, q.Serial, why)
	}
}

func (s *Server) loop() {
	for {
		select {
		case q := <-s.Queries:
			s.handle(q)
			select {
			case s.queries <- q:
			default:
			}
		case <-s.done:
			return
		}
	}
}

func (s *Server) handle(q Query) {
	s.mu.Lock()
	s.received = append(s.received, q)
	var act Action
	switch {
	case len(s.script) > 0:
		act, s.script = s.script[0], s.script[1:]
	case q.Version > s.cfg.MaxVersion:
		act = s.cfg.Unsupported
	default:
		act = Answer
	}
	s.mu.Unlock()

	version := min(q.Version, s.cfg.MaxVersion)
	switch act.kind {
	case actAnswer:
		s.answer(q, version)
	case actError:
		ev := s.cfg.MaxVersion
		if s.cfg.ErrorAtQueryVersion {
			ev = q.Version
		}
		q.Conn.Send(ErrorReport(ev, act.code, errorText(act.code)))
		if !act.keepOpen {
			q.Conn.Close()
		}
	case actFIN:
		q.Conn.Close()
	case actRST:
		q.Conn.Reset()
	case actStall:
	}
}

func errorText(code uint16) string {
	switch code {
	case CodeNoDataAvailable:
		return "No Data Available"
	case CodeUnsupportedVersion:
		return "Unsupported Protocol Version"
	default:
		return fmt.Sprintf("error %d", code)
	}
}

// answer answers a Reset Query with the whole data set, and a Serial Query
// with the deltas since its serial (or a Cache Reset if the cache cannot).
func (s *Server) answer(q Query, version uint8) {
	s.mu.Lock()
	var pdus [][]byte
	switch q.Type {
	case PDUResetQuery:
		pdus = append(pdus, CacheResponse(version, s.cfg.Session))
		for _, v := range sortedVRPs(s.vrps) {
			pdus = append(pdus, prefixPDU(version, true, v))
		}
		if version >= 2 {
			for _, c := range sortedKeys(s.aspas) {
				pdus = append(pdus, ASPA(true, c, s.aspas[c]...))
			}
		}
	case PDUSerialQuery:
		_, known := s.history[q.Serial+1]
		if q.Session != s.cfg.Session || (q.Serial != s.serial && !known) || q.Serial > s.serial {
			s.mu.Unlock()
			q.Conn.Send(CacheReset(version))
			return
		}
		pdus = append(pdus, CacheResponse(version, s.cfg.Session))
		for serial := q.Serial + 1; serial <= s.serial; serial++ {
			st := s.history[serial]
			for _, v := range st.announceVRPs {
				pdus = append(pdus, prefixPDU(version, true, v))
			}
			for _, v := range st.withdrawVRPs {
				pdus = append(pdus, prefixPDU(version, false, v))
			}
			if version >= 2 {
				for _, a := range st.announceASPAs {
					pdus = append(pdus, ASPA(true, a.Customer, a.Providers...))
				}
				for _, a := range st.withdrawASPAs {
					pdus = append(pdus, ASPA(false, a.Customer, a.Providers...))
				}
			}
		}
	default:
		s.mu.Unlock()
		return
	}
	pdus = append(pdus, EndOfData(version, s.cfg.Session, s.serial, s.cfg.Refresh, s.cfg.Retry, s.cfg.Expire))
	known := slices.ContainsFunc(s.sessions, func(sc *sessionConn) bool { return sc.conn == q.Conn })
	if !known {
		s.sessions = append(s.sessions, &sessionConn{conn: q.Conn, version: version})
	}
	s.mu.Unlock()
	q.Conn.Send(pdus...)
}

func prefixPDU(version uint8, announce bool, v VRP) []byte {
	if v.Prefix.Addr().Is4() {
		return IPv4Prefix(version, announce, v.Prefix, v.MaxLen, v.ASN)
	}
	return IPv6Prefix(version, announce, v.Prefix, v.MaxLen, v.ASN)
}

func sortedVRPs(m map[VRP]bool) []VRP {
	out := make([]VRP, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	slices.SortFunc(out, func(a, b VRP) int {
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() - b.Prefix.Bits()
		}
		if a.ASN != b.ASN {
			return int(int64(a.ASN) - int64(b.ASN))
		}
		return int(a.MaxLen) - int(b.MaxLen)
	})
	return out
}

func sortedKeys(m map[uint32][]uint32) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
