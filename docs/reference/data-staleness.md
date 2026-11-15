# Data Staleness

A cache can sync on time, every time, and still serve data that has stopped
moving: a validator that stopped re-validating, an anycast node whose
validator is stuck. And a reconnect can land on a node that serves data the
monitor saw hours ago. The anomaly detector does not see either: it scores
how a cache syncs (cadence, duration, the size of each change), not whether
its data changes. RAVEN watches the data itself, in `raven rtr monitor` and
`raven serve`.

## Data, not serials

The **data** is the cache's set of VRPs and ASPA records. It **changes** when
a sync's set differs from the set before it. Every sync record carries the
set's `data_fingerprint`, and the comparison is on that. Serials are reported
for information only. They restart with every session, differ between the
nodes behind an anycast address, and a reconnect that lands on the same data
changes the serial but not the data. ASPA Explorer saw serials 3-4-5-6, then
4-5-6, then 2-3 from one address.

So the time between data changes is measured across sessions. A reconnect
that brings back the same set does not reset the clock.

### The fingerprint

`data_fingerprint` is an order-independent fingerprint of the set: 32 hex
digits, equal for equal sets, whatever order or session the records came in.
Each record (a VRP's prefix, maxLength and origin AS, or an ASPA customer and
its sorted provider set) is hashed to 128 bits, two independent 64-bit lanes
of splitmix64 rounds. The fingerprint is the sum of those hashes modulo 2^64
in each lane, a multiset hash.

- **Upkeep:** the VRP and ASPA stores keep each cache's fingerprint next to
  its record count. Every record added or removed adds or subtracts its hash,
  so the cost is O(1) per change, full syncs included. Nothing walks the set.
- **Memory:** 16 bytes per cache per store. The tracker keeps up to 50
  earlier fingerprints per cache (about 100 bytes each, so about 5 KB) and up
  to 500 gaps (4 KB).
- **Collisions:** two different sets share a fingerprint with probability
  about 2^-64 per comparison, unless the data is built to collide. RTR data is
  not adversarial here: a cache that wanted to fool a monitor would not need
  a hash collision.

## Stale data

For each cache, RAVEN keeps the gaps between data changes: the last 500,
about five days at one change every 15 minutes. From those it learns how
long this cache's data normally goes unchanged. The data is **stale** when
the current set has been current for longer than:

```text
max(4 x median gap, 3 x 90th percentile gap, 30 minutes)
```

- Until 20 gaps are known, the threshold is **4 hours** (`threshold_source`
  `default`).
- `--stale-threshold` (`rtr.stale-threshold` in `raven serve`) sets it for
  every cache (`configured`).
- The 30-minute floor keeps a cache whose data changes every few minutes from
  being called stale after ten.
- The data age is checked at every sync and every 15 seconds in between,
  in `raven rtr monitor` and `raven serve` alike. A cache goes stale when its
  data outlasts the threshold, not at its next sync. A cache that stops
  syncing altogether, connected or not, goes stale too: the data in use is
  just as old. (`raven_rtr_data_expired` says, in addition, that no sync
  completed within the Expire Interval.)

A stale episode gives **one** `stale` record when it begins, never one per
sync. It gives one `stale_resolved` record when the data changes again. In
`raven rtr monitor`, the `stale` record comes with a structural `anomaly`
(trigger `data_stale`).

**Scope:** when `raven rtr monitor` compares several caches, the `stale`
record says whether every compared cache went stale within the settle window
(`scope` `upstream`: the data stopped at its source, or at every validator
alike) or only some did (`local`). The record is held until that is known. It
is released as soon as every compared cache is stale, or once the settle
window has passed since the cache went stale, at the next sync or 15-second
check.

The learned gaps are saved in the anomaly snapshot (`--anomaly-snapshot`) and
seeded by `raven rtr seed-baseline`, as `data_gaps`, an additive field.
Snapshots from earlier releases load with no gap history.

### Connected or disconnected

The age is checked between syncs, so a cache goes stale whether or not it
syncs. Each `stale` record says which case it is, as `cache_state`, as of
when the episode began:

- **`connected`**: the cache answers, and syncs on time or not, but its data
  does not change. It is serving **frozen data**: a validator that stopped
  re-validating, a stuck anycast node. Routers using that cache see the same
  frozen data.
- **`disconnected`**: RAVEN has no session with the cache, and the cache's
  **last data, still in use, ages**. The cache cannot be reached: a
  restart, a network problem. What it serves meanwhile is unknown.
  `raven_rtr_session_state` and `disconnected` records say the same from
  the connection side.

A disconnected cache that reconnects with the same data stays in the same
episode: its data is as old as before. The episode ends with a
`stale_resolved` whose `resolution` says how: `data_change` (the data
changed within a session) or `reconnect_new_data` (the first sync of a new
session brought new data). The `rtr_stale` webhook carries `cache_state` in
its `data`, and `raven_rtr_stale` has a `cache_state` label, so an alert can
treat the two cases apart.

On ASPA Explorer's records, the anycast stalls were `connected` and ended by
`reconnect_new_data` (a reconnect reached another node). Their Routinator,
disconnected from 08:10 to 10:28 on 15 November, was stale `disconnected`
from 09:02, and its reconnect with a full sync at serial 0 ended the episode
(`reconnect_new_data`).

## Return to earlier data

After every sync, full or incremental, the tracker compares the set's
fingerprint with those of the cache's recent sets: the last 50, none that
stopped being current more than 7 days ago. A sync whose set is one of those,
and not the current one, is a **return to earlier data** if it is
significant: that set was current, in all, for longer than the cache's
stale threshold, or stopped being current longer ago than that threshold.
Such a return is reported as
`data_regressed`, with when that set was first and last current and the
serials before and after. A structural `anomaly` (trigger `data_regressed`)
comes with it.

A return is **not a data change**. It does not end a stale episode, and it
adds no gap. The data is as old as the set it returned to, so the staleness
clock runs from when that set was **first** current. A cache that returns to
a set from hours ago is stale at once if that age is past its threshold.

A return that is not significant is a normal data change: the set's
earlier stints are forgotten, and its time as current starts over. This is
churn. A cache whose syncs add records and remove them again in the next
(DaKnObNET's 23 announced and 23 withdrawn, say) toggles between two sets,
each current for one refresh interval and gone for one. It is never
`data_regressed`, and never stale.

What still looks like a return: a record that stays added for longer than
the threshold, or stays removed for longer, and then goes back. That set did
hold for a while, and is reported as `data_regressed`, with the data age of
the set it returned to.

## Records

The record types, their fields and the JSON Schema are in
[Telemetry NDJSON](telemetry-ndjson.md#data-staleness). Each record is
summarized here with a real example line.

### `stale`

| Field | Meaning |
|---|---|
| `serial` | The serial at detection (for information) |
| `last_change` | When the current set became current. For a return to earlier data, when that set was first current |
| `gap_ns` | Nanoseconds from `last_change` to this record |
| `expected_gap_ns` | The threshold `gap_ns` exceeded |
| `syncs_without_change` | Syncs since the last data change that saw none |
| `threshold_source` | `learned`, `default` (fewer than 20 gaps) or `configured` |
| `gaps_learned` | Gaps the threshold had to learn from (at most 500) |
| `scope` | With several `--cache`: `upstream` or `local`. Absent with one |
| `cache_state` | `connected` or `disconnected`, as the episode began ([below](#connected-or-disconnected)) |

```json
{"timestamp":"2026-11-12T05:50:37.241328231Z","cache":"rtr.rpki.cloudflare.com:8282","event_type":"stale","schema_version":1,"serial":3,"last_change":"2026-11-12T04:49:43.051994426Z","gap_ns":3654189333805,"expected_gap_ns":3646165513965,"syncs_without_change":1,"threshold_source":"learned","gaps_learned":232,"cache_state":"connected"}
```

### `stale_resolved`

| Field | Meaning |
|---|---|
| `stale_since`, `duration_ns` | When the `stale` record was written, and how long the episode lasted |
| `last_change`, `gap_ns` | When the stale data became current, and how long it went unchanged |
| `serial_before`, `serial_after` | The serials around the sync that changed the data |
| `sync_type` | That sync's type |
| `resolution` | `data_change`: the data changed within a session. `reconnect_new_data`: the first sync after a reconnect brought new data |
| `vrp_added`, `vrp_removed`, `aspa_added`, `aspa_removed` | That sync's net change |

```json
{"timestamp":"2026-11-13T20:12:00.138159203Z","cache":"rtr.rpki.cloudflare.com:8282","event_type":"stale_resolved","schema_version":1,"stale_since":"2026-11-12T05:50:37.241328231Z","duration_ns":138082896830972,"last_change":"2026-11-12T04:49:43.051994426Z","gap_ns":141737086164777,"serial_before":3,"serial_after":5,"sync_type":"full","resolution":"reconnect_new_data","vrp_added":0,"vrp_removed":0,"aspa_added":0,"aspa_removed":0}
```

That line replays a record from before the net counts, so they are 0. A
current RAVEN writes the sync's own.

### `data_regressed`

| Field | Meaning |
|---|---|
| `serial_before`, `serial_after` | The serials around the sync |
| `sync_type` | `incremental`: inside a session. `full`: typically after a reconnect |
| `data_fingerprint` | The earlier set's fingerprint |
| `first_current` | When that set was first current. The staleness clock runs from here |
| `last_current`, `ago_ns` | When that set stopped being current, and how long ago that was |

```json
{"timestamp":"2026-11-15T16:41:03.443352981Z","cache":"127.0.0.1:46123","event_type":"data_regressed","schema_version":1,"serial_before":2,"serial_after":3,"sync_type":"incremental","data_fingerprint":"8e7f67a7118e090cefc14204e7a6144c","first_current":"2026-11-15T16:41:03.030132968Z","last_current":"2026-11-15T16:41:03.032053563Z","ago_ns":411299418}
```

## Two real cases

### Routinator on AS38016, 5 October 2026

The data changed every 10 to 20 minutes. Then it did not change for 90
minutes, and a drop of about 11,000 VRPs followed. With gaps of 10 to 20
minutes, the median is about 15 minutes and the 90th percentile about
20 minutes. The threshold is therefore about one hour: 4 x 15 = 3 x 20 = 60
minutes. RAVEN reports `stale` as the hour passes, about 30 minutes before
the drop. The synthetic test of this case (changes at 10, 12,
14, 16, 18 and 20 minutes for a day, then syncs every 10 minutes with new
serials and no change) learns exactly 1h from 96 gaps. It is stale at
60m15s (the first 15-second check past the hour, before the 70-minute
sync), once, and resolved by the next change.

### Anycast-node stall, seen by ASPA Explorer, 12 to 13 November 2026

One node behind `rtr.rpki.cloudflare.com:8282` served the same 1,033,733 VRPs
from 04:49 on 12 November to 19:49 on 13 November UTC. That is 40 hourly
syncs, 39 of them with `serial_changed` false. Replayed from ASPA Explorer's
NDJSON (`internal/telemetry/testdata/anycast-node-stall-2026-11-12.ndjson`):

| Time (UTC) | What happened | Record |
|---|---|---|
| 12 Nov 04:49 | Start of the stall | Threshold learned from 231 gaps: **1h00m46s** |
| 12 Nov 05:49 | First hourly sync: 60m00s unchanged, 46 s under the threshold | none |
| 12 Nov 05:50:37 | The first 15-second check past the threshold: 1h00m54s unchanged | `stale` (one, for the whole stall) |
| 13 Nov 20:12 | Reconnect to fresh data (1,034,990 VRPs) | `stale_resolved`: 39h22m unchanged |
| 13 Nov 21:12 | Reconnect back to 1,033,733 at serial 3 | `data_regressed` (first current 12 Nov 04:49, current 39h in all), then `stale` at once: that data is 40h old |

The file also holds an earlier stall on 9 to 10 November: 1,032,530 VRPs at
serial 5 from 17:41 to 03:42, synced hourly. RAVEN reports it as `stale` at
21:41 (at the sync, 1.5 s past the threshold and before the next check) with
the 4-hour default, because only 8 gaps were known by then.

These records predate `data_fingerprint` and the net counts. For records
without a fingerprint, the tracker uses a stand-in:

- The data changed if an incremental sync announced or withdrew anything, or
  if the totals moved.
- Equal totals at the same serial, after different data, count as the same
  set. This only matches a set that at least two syncs saw. Totals move like
  a random walk and serials restart every session, so without that rule,
  serial and totals matched five one-sync sets by chance before the stall.

The stand-in does not recognize the return at 04:49 on 12 November: the data
went back to the total of 04:34, but at serial 3 instead of 6. With real
fingerprints it would be a `data_regressed` if the set was the same.

## In raven serve

- `raven_rtr_data_age_seconds{cache}`: how long the current set has been
  current. Updated at every sync and every 15 s.
- `raven_rtr_stale{cache,cache_state}`: 1 during a stale episode, on the
  series of the episode's `cache_state` (`connected` or `disconnected`), 0 on
  the other; both 0 when the data is not stale.
- `raven_rtr_data_regressions_total{cache}`: returns to earlier data.
- A WARN log line when an episode starts (with `cache_state`) and on a
  return, and an INFO line when an episode ends (with `resolution`).
- Event triggers `rtr_stale` and `rtr_data_regressed`, one event per episode
  and per return. Like `rtr_bulk_change`, they reach only notification
  actions (webhook, log), never FlowSpec. Stale data is no reason to filter
  traffic. See [Configuration](../user-guide/configuration.md) and the
  example alert in [Observability](../user-guide/observability.md#data-staleness).
