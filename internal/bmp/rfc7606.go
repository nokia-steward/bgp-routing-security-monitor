package bmp

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"github.com/nokia-steward/bgp-routing-security-monitor/internal/metrics"
	"github.com/nokia-steward/bgp-routing-security-monitor/internal/types"
)

// RAVEN mirrors the RFC 7606 error handling the monitored router applies to
// a malformed UPDATE, so its table holds what the router's Adj-RIB-In
// holds. See parseBGPUpdate for how each approach is applied.

// errAction is an RFC 7606 §2 error-handling approach, weakest first.
type errAction uint8

const (
	actNone errAction = iota
	actAttributeDiscard
	actTreatAsWithdraw
	actSessionReset
)

func (a errAction) String() string {
	switch a {
	case actAttributeDiscard:
		return metrics.MalformedActionAttributeDiscard
	case actTreatAsWithdraw:
		return metrics.MalformedActionTreatAsWithdraw
	case actSessionReset:
		return metrics.MalformedActionSessionReset
	}
	return "none"
}

// malformation is how an UPDATE was found malformed: the strongest approach
// its errors call for (RFC 7606 §3 (h)) and the first error that called for
// it. The zero value is a well-formed UPDATE.
type malformation struct {
	action errAction
	reason string // a metrics.MalformedReason* value
	detail string // what was wrong, for the log
}

// add records an error. A weaker or equal one than already recorded changes
// nothing, so the result does not depend on anything but the input.
func (m *malformation) add(a errAction, reason, detail string) {
	if a > m.action {
		*m = malformation{action: a, reason: reason, detail: detail}
	}
}

// Path attribute flag bits (RFC 4271 §4.3).
const (
	attrFlagOptional   = 0x80
	attrFlagTransitive = 0x40
	attrFlagExtLen     = 0x10
)

// flagsAre reports whether an attribute's Optional and Transitive bits are
// as given. Only those two are checked (RFC 7606 §3 (c)).
func flagsAre(flags byte, optional, transitive bool) bool {
	return (flags&attrFlagOptional != 0) == optional && (flags&attrFlagTransitive != 0) == transitive
}

// asWithdrawals turns routes into withdrawals of the same keys.
func asWithdrawals(routes []types.Route) []types.Withdrawal {
	out := make([]types.Withdrawal, 0, len(routes))
	for i := range routes {
		r := &routes[i]
		out = append(out, types.Withdrawal{
			Router:            r.Router,
			PeerDistinguisher: r.PeerDistinguisher,
			PeerAddr:          r.PeerAddr,
			Prefix:            r.Prefix,
			PathID:            r.PathID,
			RIBType:           r.RIBType,
		})
	}
	return out
}

// malformedWarnInterval is the least time between two WARNs for one peer
// and reason; those in between are counted and the count given with the
// next. The metric counts every one.
const malformedWarnInterval = time.Minute

type warnKey struct {
	peer   PeerKey
	reason string
}

type warnState struct {
	last       time.Time
	suppressed int
}

// warnLimiter rate-limits a log line per key.
type warnLimiter struct {
	mu   sync.Mutex
	keys map[warnKey]*warnState
}

// warnLimiterMaxKeys bounds the limiter's map; past it, entries idle for an
// interval are dropped.
const warnLimiterMaxKeys = 4096

// allow reports whether to log for k at now and, if so, how many were
// suppressed since the last one logged.
func (w *warnLimiter) allow(k warnKey, now time.Time) (bool, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.keys == nil {
		w.keys = make(map[warnKey]*warnState)
	}
	st, ok := w.keys[k]
	if ok && now.Sub(st.last) < malformedWarnInterval {
		st.suppressed++
		return false, 0
	}
	if !ok {
		if len(w.keys) >= warnLimiterMaxKeys {
			for key, s := range w.keys {
				if now.Sub(s.last) >= malformedWarnInterval {
					delete(w.keys, key)
				}
			}
		}
		st = &warnState{}
		w.keys[k] = st
	}
	suppressed := st.suppressed
	st.last, st.suppressed = now, 0
	return true, suppressed
}

// reportMalformed counts a malformed UPDATE and logs it: a WARN, at most one
// a minute per peer and reason, and, at debug level, the whole UPDATE (RFC
// 7606 §6 asks for both the NLRI involved and the message).
func (l *Listener) reportMalformed(log *slog.Logger, sysName string, key PeerKey, pph BMPPerPeerHeader,
	m malformation, withdrawals int, update []byte) {
	metrics.BMPMalformedUpdatesTotal.WithLabelValues(m.action.String(), m.reason).Inc()
	if log.Enabled(context.Background(), slog.LevelDebug) {
		log.Debug("malformed BGP UPDATE", "peer", pph.PeerAddr, "action", m.action.String(),
			"reason", m.reason, "update", hex.EncodeToString(update))
	}
	ok, suppressed := l.malformedWarn.allow(warnKey{peer: key, reason: m.reason}, time.Now())
	if !ok {
		return
	}
	log.Warn("malformed BGP UPDATE from peer",
		"router_name", sysName,
		"peer", pph.PeerAddr,
		"peer_asn", pph.PeerASN,
		"peer_distinguisher", types.FormatRD(key.Distinguisher),
		"rib", ribTypeOf(pph).String(),
		"action", m.action.String(),
		"reason", m.reason,
		"detail", m.detail,
		"withdrawals", withdrawals,
		"suppressed", suppressed,
	)
}
