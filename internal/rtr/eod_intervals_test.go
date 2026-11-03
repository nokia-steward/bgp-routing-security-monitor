package rtr

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
)

// eodPayload is an End of Data payload (after the header) for versions 1
// and 2: serial, then the Refresh, Retry and Expire Intervals.
func eodPayload(serial, refresh, retry, expire uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:4], serial)
	binary.BigEndian.PutUint32(b[4:8], refresh)
	binary.BigEndian.PutUint32(b[8:12], retry)
	binary.BigEndian.PutUint32(b[12:16], expire)
	return b
}

// An out-of-range End of Data interval is clamped to the nearest bound of
// its RFC 8210 §6 range, with a WARN naming the received and clamped
// values; an in-range one is taken as sent, without a WARN. Each case
// varies one interval and keeps the other two in range.
func TestEndOfDataIntervalsClamped(t *testing.T) {
	type tc struct {
		name     string
		interval string // "refresh", "retry" or "expire"
		in, want uint32
	}
	var cases []tc
	for _, iv := range []struct {
		name   string
		valid  [2]uint32
		inside uint32
	}{
		{"refresh", [2]uint32{1, 86400}, 3600},
		{"retry", [2]uint32{1, 7200}, 600},
		{"expire", [2]uint32{600, 172800}, 7200},
	} {
		lo, hi := iv.valid[0], iv.valid[1]
		cases = append(cases,
			tc{"below min", iv.name, lo - 1, lo},
			tc{"min", iv.name, lo, lo},
			tc{"in range", iv.name, iv.inside, iv.inside},
			tc{"max", iv.name, hi, hi},
			tc{"above max", iv.name, hi + 1, hi},
		)
		if lo-1 != 0 {
			cases = append(cases, tc{"zero", iv.name, 0, lo})
		}
		cases = append(cases, tc{"uint32 max", iv.name, ^uint32(0), hi})
	}

	for _, c := range cases {
		t.Run(c.interval+"/"+c.name, func(t *testing.T) {
			refresh, retry, expire := uint32(1800), uint32(300), uint32(3600)
			switch c.interval {
			case "refresh":
				refresh = c.in
			case "retry":
				retry = c.in
			case "expire":
				expire = c.in
			}
			logs := &lockedBuffer{}
			cl := &Client{log: slog.New(slog.NewTextHandler(logs, nil))}
			for _, version := range []uint8{1, 2} {
				eod, err := cl.parseEndOfData(version, eodPayload(9, refresh, retry, expire))
				if err != nil {
					t.Fatal(err)
				}
				got := map[string]uint32{"refresh": eod.refresh, "retry": eod.retry, "expire": eod.expire}
				want := map[string]uint32{"refresh": 1800, "retry": 300, "expire": 3600}
				want[c.interval] = c.want
				for k := range want {
					if got[k] != want[k] {
						t.Errorf("v%d: %s %d sent: %s = %d, want %d", version, c.interval, c.in, k, got[k], want[k])
					}
				}
				if eod.serial != 9 {
					t.Errorf("v%d: serial = %d, want 9", version, eod.serial)
				}
			}
			warn := fmt.Sprintf(`level=WARN msg="cache sent an out-of-range End of Data interval; clamped" interval=%s value=%d clamped=%d`,
				c.interval, c.in, c.want)
			if c.in != c.want && !strings.Contains(logs.String(), warn) {
				t.Errorf("no WARN %q; logs:\n%s", warn, logs)
			}
			if c.in == c.want && strings.Contains(logs.String(), "level=WARN") {
				t.Errorf("WARN for an in-range interval; logs:\n%s", logs)
			}
		})
	}
}

// With no intervals received, the RFC 8210 §6 defaults apply: RTR version 0,
// whose End of Data carries only the serial, and a version 1 or 2 End of
// Data too short to hold them.
func TestEndOfDataWithoutIntervalsUsesDefaults(t *testing.T) {
	logs := &lockedBuffer{}
	cl := &Client{log: slog.New(slog.NewTextHandler(logs, nil))}
	for _, in := range []struct {
		version uint8
		data    []byte
	}{
		{0, eodPayload(9, 0, 0, 0)[:4]},
		{0, eodPayload(9, 0, 0, 0)}, // v0 ignores trailing bytes
		{1, eodPayload(9, 0, 0, 0)[:4]},
		{2, eodPayload(9, 0, 0, 0)[:12]},
	} {
		eod, err := cl.parseEndOfData(in.version, in.data)
		if err != nil {
			t.Fatal(err)
		}
		if eod.refresh != defaultRefresh || eod.retry != defaultRetry || eod.expire != defaultExpire {
			t.Errorf("v%d, %d bytes: intervals %d/%d/%d, want the defaults %d/%d/%d", in.version, len(in.data),
				eod.refresh, eod.retry, eod.expire, defaultRefresh, defaultRetry, defaultExpire)
		}
	}
	if strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("WARN without received intervals; logs:\n%s", logs)
	}

	// Before the first End of Data, too.
	c, err := NewClient("127.0.0.1:0", "tcp", nil, nil, nil, 2, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if c.refresh != defaultRefresh || c.retry != defaultRetry || c.expire != defaultExpire {
		t.Errorf("new client intervals %d/%d/%d, want the defaults", c.refresh, c.retry, c.expire)
	}
}

// A cache's Refresh Interval of 0 means "refresh now": it is clamped to 1 s
// and the next poll goes out after 1 s, not after the 3600 s default. With a
// static serial there is no Serial Notify, so a 3600 s refresh left the
// session silent for an hour. Expire 0 is clamped to 600, and that is the
// effective expire.
func TestRefreshZeroPollsAfterOneSecond(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.start(t)

	_, eod := fullSync(t, cache, 2, 41, 0, 600, 0)
	tc.synced(t)

	// One second lasts 1ms here; the default would poll after 3.6s.
	q := cache.Next(1500 * time.Millisecond)
	if q.Type != rtrtest.PDUSerialQuery || q.Serial != 41 || q.Session != 7 {
		t.Fatalf("got query type %d serial %d session %d, want a Serial Query for serial 41, session 7",
			q.Type, q.Serial, q.Session)
	}
	if gap := q.At.Sub(eod); gap > 500*time.Millisecond {
		t.Errorf("poll came %v after the End of Data, want the clamped 1 s refresh (1ms here), not 3600 s", gap)
	}

	logs := tc.logs.String()
	for _, want := range []string{
		"interval=refresh value=0 clamped=1",
		"interval=expire value=0 clamped=600",
		"refresh=1 retry=600 expire=600 expire_effective=600",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
}

// rtr.expire-interval still replaces the cache's Expire Interval when the
// cache's is out of range: the clamped value is logged, the override is in
// effect.
func TestExpireOverrideWinsOverClampedExpire(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	tc.SetExpireOverride(3600)
	tc.start(t)

	fullSync(t, cache, 2, 41, 100, 600, 999999)
	tc.synced(t)

	if got := tc.ExpireInterval(); got != 3600 {
		t.Errorf("ExpireInterval() = %d, want the 3600 override", got)
	}
	logs := tc.logs.String()
	for _, want := range []string{
		"interval=expire value=999999 clamped=172800",
		"expire=172800 expire_effective=3600",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
}
