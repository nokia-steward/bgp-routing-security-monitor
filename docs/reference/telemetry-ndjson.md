# Telemetry NDJSON

`raven rtr monitor` writes one JSON object per line (NDJSON) to `--log-file`:
the RTR session's lifecycle, every completed sync, and every anomaly the
detector finds. Run against several caches (`--cache` repeated), it writes
each cache's records to the same file, told apart by `cache`, and adds the
records of its [comparison of the caches](#comparing-caches). This page is the contract for that output: what each record
type means, its fields, and what may change. Tools that parse the stream,
such as [ASPA Explorer](https://aspa.ping6.it/statistics.html#rtr-title),
build against it.

The machine-readable form is the JSON Schema
[`schema/rtr-monitor-ndjson.v1.json`](https://github.com/nokia-steward/bgp-routing-security-monitor/blob/main/schema/rtr-monitor-ndjson.v1.json)
(draft 2020-12). RAVEN's tests check every record the monitor writes
against it, and fail when the code and the contract drift apart.

This page describes `schema_version` 1.

## Compatibility policy

- Every record has `schema_version`, an integer. This contract is version 1.
  Records without it were written by a RAVEN from before the contract.
  Parse them as version 1, but expect less: RAVEN v0.4.0 and earlier write
  no `disconnected` or `version_downgrade` records, omit `proto_version`
  when it is 0 and never write it on `sync` and `reset`, and record an Error
  Report code 4 during version negotiation as an `error` (and an anomaly).
- **Older files differ in two more ways** that this contract already allows
  for. Their `timestamp` may carry the monitor host's local offset
  (`-08:00`) instead of `Z`: honor the offset, as the contract requires.
  And their `sync` records leave out `serial`, the counts and
  `sync_duration_ns` when they are 0: there, an absent field means 0.
- **Within a `schema_version`, changes are additive only:** new fields, new
  record types, new enum values. A field that exists keeps its name, its
  JSON type and its meaning.
- **Consumers must ignore fields and record types they do not know**, and
  should handle an enum value they do not know (a new `disconnect_reason`,
  say) as "other". A consumer that rejects unknown fields will break on a
  minor release. The JSON Schema is strict (`additionalProperties: false`)
  because RAVEN's own tests use it to catch drift; to validate with it, allow
  additional properties.
- **Removing, renaming or retyping anything requires a new
  `schema_version`**, a new schema file (`rtr-monitor-ndjson.v2.json`), and
  an announcement in the [Changelog](../CHANGELOG.md) at least one release
  before it ships.

## Reading the stream

- One record per line, UTF-8, each a JSON object. The file is appended to,
  never rewritten: a monitor restart continues the same file.
- **Optional fields are absent, not null.** A conditional field is present
  exactly when its condition holds (see each record type). On `sync`,
  `serial`, the counts and `sync_duration_ns` are always present, 0
  included; files from older releases omit them when 0, so there absent
  means 0.
- `event_type` says which record it is. Branch on it, not on which fields
  are present.
- Records are written in the order the events happen, with one exception:
  an `anomaly` record is written by the detector, which runs alongside the
  session, so it can come after records that followed the one it is about.
  It has that record's `timestamp` and `cache`; match on those. An
  `upstream_change` is written by the same detector path, so it can come
  late in the same way.
- Strings are JSON-escaped by Go's encoder: `<`, `>` and `&` appear as
  `\u003c`, `\u003e`, `\u0026`. Use a JSON parser, not text matching.
- Durations are integers in nanoseconds (`*_ns`). Counts are integers.

### Fields on every record

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | `1` |
| `timestamp` | string | When the event happened: RFC 3339 with up to nanosecond precision (trailing zeros trimmed) and a UTC offset, which consumers must honor. RAVEN writes UTC (`2026-11-11T21:06:49.0886Z`) from this release; files from older releases may carry the monitor host's local offset (`2026-11-11T13:06:49.0886-08:00`) |
| `cache` | string | The RTR cache, exactly as given to `--cache` (`host:port`). On the comparison records, the cache the record is about (`divergence`, `divergence_resolved`) or whose sync completed the match (`upstream_change`) |
| `event_type` | string | The record type: one of the sections below |

Every record type except `anomaly` and the comparison records
(`divergence`, `divergence_resolved`, `upstream_change`) also has:

| Field | Type | Meaning |
|---|---|---|
| `proto_version` | integer | RTR protocol version of the session: `0`, `1` or `2`. Always present, `0` included. Version 0 and 1 carry no ASPA. On `connected` and `version_downgrade` it is the version the monitor asked for; on the others the session's |

## Record types

The examples are records the monitor wrote in RAVEN's test harness; only the
`cache` address was changed.

### `connected`

The monitor opened a connection (TCP or TLS) to the cache and is about to send
its first query. Every `connected` is followed, eventually, by exactly one
`disconnected`.

| Field | Type | Presence |
|---|---|---|
| `proto_version` | integer | always: the version the first query asks for |

```json
{"timestamp":"2026-11-11T21:06:49.088605681Z","cache":"rtr.example.net:3323","event_type":"connected","schema_version":1,"proto_version":2}
```

### `sync`

A sync completed: the cache sent End of Data. A full sync answers a Reset
Query (the whole data set); an incremental one a Serial Query (the changes
since the last serial), including a poll that finds nothing new.

Every field but `interval_since_ns` is always present, 0 included. Files
from older releases omit `serial`, the counts and `sync_duration_ns` when
they are 0, and have no `vrp_added`, `vrp_removed`, `aspa_added` or
`aspa_removed`.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `sync_type` | string | always | `full` or `incremental` |
| `serial_changed` | boolean | always | The serial differs from the previous sync's, in this process, across sessions: `true` on the first sync; a full sync of a new session can be `false` |
| `serial` | integer | always, 0 included | The cache's serial from End of Data (0 to 4294967295) |
| `vrp_total` | integer | always, 0 included | Distinct VRPs this cache holds after the sync. A VRP the cache announced twice counts once |
| `vrp_announced` | integer | always, 0 included | VRP announcement PDUs received in this sync (IPv4 and IPv6), re-announcements included. On a full sync, the whole set |
| `vrp_withdrawn` | integer | always, 0 included | VRP withdrawal PDUs received in this sync |
| `vrp_added` | integer | always, 0 included | VRPs this cache came to hold in this sync: the net change. On a full sync, against the cache's data before it |
| `vrp_removed` | integer | always, 0 included | VRPs this cache stopped holding in this sync: the net change. On a full sync, against the cache's data before it |
| `aspa_total` | integer | always, 0 included | ASPA records held after the sync: customer ASes. 0 below RTR version 2 |
| `aspa_announced` | integer | always, 0 included | ASPA announcement PDUs received in this sync (one per customer AS) |
| `aspa_withdrawn` | integer | always, 0 included | ASPA withdrawal PDUs received in this sync |
| `aspa_added` | integer | always, 0 included | Customer ASes this cache came to hold a record for in this sync. A provider-set replacement is neither added nor removed |
| `aspa_removed` | integer | always, 0 included | Customer ASes whose record this cache stopped holding in this sync |
| `sync_duration_ns` | integer | always, 0 included | Nanoseconds from sending the query to receiving End of Data |
| `interval_since_ns` | integer | absent on the first sync of the process | Nanoseconds since the previous sync's End of Data in this process, across sessions |

```json
{"timestamp":"2026-11-11T21:06:49.089760506Z","cache":"rtr.example.net:3323","event_type":"sync","schema_version":1,"sync_type":"full","serial_changed":true,"proto_version":1,"serial":0,"vrp_total":0,"vrp_announced":0,"vrp_withdrawn":0,"vrp_added":0,"vrp_removed":0,"aspa_total":0,"aspa_announced":0,"aspa_withdrawn":0,"aspa_added":0,"aspa_removed":0,"sync_duration_ns":318784}
{"timestamp":"2026-11-11T21:06:49.091708344Z","cache":"rtr.example.net:3323","event_type":"sync","schema_version":1,"sync_type":"full","serial_changed":true,"proto_version":2,"serial":0,"vrp_total":50,"vrp_announced":50,"vrp_withdrawn":0,"vrp_added":50,"vrp_removed":0,"aspa_total":2,"aspa_announced":2,"aspa_withdrawn":0,"aspa_added":2,"aspa_removed":0,"sync_duration_ns":1369810}
{"timestamp":"2026-11-11T21:06:49.097425939Z","cache":"rtr.example.net:3323","event_type":"sync","schema_version":1,"interval_since_ns":5717680,"sync_type":"incremental","serial_changed":true,"proto_version":2,"serial":1,"vrp_total":1247,"vrp_announced":1200,"vrp_withdrawn":3,"vrp_added":1200,"vrp_removed":3,"aspa_total":2,"aspa_announced":1,"aspa_withdrawn":1,"aspa_added":1,"aspa_removed":1,"sync_duration_ns":1897959}
```

#### PDUs received and net change

`vrp_announced`, `vrp_withdrawn`, `aspa_announced` and `aspa_withdrawn`
count the PDUs the cache sent. `vrp_added`, `vrp_removed`, `aspa_added`
and `aspa_removed` count what changed: the records this cache came to hold,
or stopped holding, by the end of the sync. A record it held before and
still holds after counts in neither, whatever PDUs it took.

For a correct cache's incremental sync they agree: every announcement adds
a record, every withdrawal removes one. They differ when the cache announces
what it holds (a duplicate announcement, error code 7). Fort 1.7.0's delta
from serial 220 to 221 (NICMx/FORT-validator#204) sent 2276 VRP
announcements and 2263 withdrawals: 2255 records the client held were
announced again and then withdrawn. Only 21 VRPs were new and 8 withdrawn
for good. The sync record, its other fields left out:

```text
{"event_type":"sync","sync_type":"incremental","serial":221,"vrp_total":2276,"vrp_announced":2276,"vrp_withdrawn":2263,"vrp_added":21,"vrp_removed":8, ...}
```

Two legitimate cases differ too, with no error: an ASPA announcement for a
customer the cache already has a record for replaces its provider set
(8210bis §5.12) and counts in `aspa_announced` but not `aspa_added`; and a
record announced and withdrawn again in one sync counts one of each PDU and
no net change.

On a full sync the PDU counts are the cache's whole data set, and the net
counts its difference from the data the cache had before: a resync that
returns the same data has `vrp_added` and `vrp_removed` 0.

### `reset`

The cache sent a Cache Reset: it cannot answer the monitor's Serial Query
incrementally. A full sync follows. The detector reports every reset as a
structural anomaly.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `reset_reason` | string | always | `cache_reset_pdu` |

```json
{"timestamp":"2026-11-11T21:06:49.10142665Z","cache":"rtr.example.net:3323","event_type":"reset","schema_version":1,"reset_reason":"cache_reset_pdu","proto_version":2}
```

### `error`

The cache sent an Error Report that is a fault: any code but 2, and code 4
(Unsupported Protocol Version) on a session that was already established, at
version 0, or at a version pinned with `--rtr-version`. The session ends (a
`disconnected` follows). The detector reports every `error` as a structural
anomaly.

An `error` with `error_origin` `client` is one RAVEN found in what the cache
sent, not an Error Report from the cache:

- code 7 (Duplicate Announcement Received): the cache announced a VRP it
  already held, without withdrawing it first;
- code 6 (Withdrawal of Unknown Record): the cache withdrew a VRP, or an ASPA
  customer AS, it did not hold.

RAVEN writes one such record per sync and code, with `error_count`, before
the sync's `sync` record. The detector reports each as a structural anomaly
with trigger `protocol_error`.

**RAVEN deviates from RFC 8210 §12 here.** §12 makes codes 6 and 7 fatal: the
router drops the session (and, in draft-ietf-sidrops-8210bis, flushes the
cache's data). A monitor must not flush its data because of a cache bug:
every route it validates would turn NotFound until the cache recovered.
Instead RAVEN keeps a count per VRP and per cache, announcements less
withdrawals, never below 0, and holds the VRP while the count is above 0.
Fort 1.7.0 (NICMx/FORT-validator#204) announces VRPs the router holds and
withdraws them in the same answer, meaning no change: with the count they
stay, as the cache meant. A router that ignores the duplicate announcement
and applies the withdrawal loses them. After a sync with either error RAVEN
sends a Reset Query on the same session, at most once per 5 minutes per
cache. The full sync that answers it replaces the cache's data at its End of
Data, so validation never sees a gap. The session goes on: no
`disconnected` follows. The `sync` record of that resync has `sync_type`
`full`.

An ASPA announcement for a customer AS the cache already announced is not an
error: draft-ietf-sidrops-8210bis §5.12 makes it a replacement of that
customer's provider set, so ASPA records have no count. An ASPA
announcement followed by a withdrawal of the same customer in one delta
raises no error and no resync: the record is removed, as the stream says. A
withdrawal carries no provider list (a 12-byte PDU) and removes the
customer's whole record.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `error_code` | integer | always | The RFC 8210 §12 error code; with `error_origin`, `6` or `7` |
| `error_text` | string | absent when the cache sent none | The cache's error text, or RAVEN's description of the error it found (not stable: do not parse it) |
| `error_origin` | string | only when RAVEN found the error | `client` |
| `error_count` | integer | with `error_origin` | How many PDUs of the sync had the error |

```json
{"timestamp":"2026-11-11T21:06:49.107152206Z","cache":"rtr.example.net:3323","event_type":"error","schema_version":1,"error_text":"Corrupt Data","error_code":0,"proto_version":2}
{"timestamp":"2026-11-12T09:14:02.551203117Z","cache":"rtr.example.net:3323","event_type":"error","schema_version":1,"error_text":"duplicate announcement received: 2255 records announced again while this cache held them, first 192.0.2.0/24 max-length 24 AS64500; counted","error_code":7,"error_origin":"client","error_count":2255,"proto_version":2}
{"timestamp":"2026-11-12T09:14:02.551240003Z","cache":"rtr.example.net:3323","event_type":"error","schema_version":1,"error_text":"withdrawal of unknown record: 1 records withdrawn that this cache did not hold, first 198.51.100.0/24 max-length 24 AS64501; ignored","error_code":6,"error_origin":"client","error_count":1,"proto_version":2}
```

### `cache_not_ready`

The cache sent Error Report code 2 (No Data Available): it is still building
its first data set, as Routinator does at startup. Not a fault and not an
anomaly. The monitor retries at the same version.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `error_code` | integer | always | `2` |
| `error_text` | string | absent when the cache sent none | The cache's error text |

```json
{"timestamp":"2026-11-11T21:06:49.088609865Z","cache":"rtr.example.net:3323","event_type":"cache_not_ready","schema_version":1,"error_text":"No Data Available","error_code":2,"proto_version":2}
```

### `version_downgrade`

A step of version negotiation: the cache turned down `proto_version` before
answering anything on the session, and the monitor retries at
`next_proto_version`. Expected against a cache that speaks an older version;
not a fault and not an anomaly. The session's own `disconnected` comes too.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `next_proto_version` | integer | always | The version the monitor retries at: `0`, `1` or `2` |
| `downgrade_reason` | string | always | `unsupported_version` (Error Report code 4) or `session_dropped` (the cache closed or reset the connection before answering; the monitor retries once at the next lower version) |
| `error_code` | integer | with `unsupported_version` | `4` |
| `error_text` | string | with `unsupported_version`, when the cache sent text | The cache's error text |
| `disconnect_reason` | string | with `session_dropped` | How the connection ended: `eof` or `reset` |

```json
{"timestamp":"2026-11-11T21:06:49.088827904Z","cache":"rtr.example.net:3323","event_type":"version_downgrade","schema_version":1,"error_text":"Unsupported Protocol Version","error_code":4,"proto_version":2,"next_proto_version":1,"downgrade_reason":"unsupported_version"}
{"timestamp":"2026-11-11T21:06:49.088670322Z","cache":"rtr.example.net:3323","event_type":"version_downgrade","schema_version":1,"proto_version":2,"disconnect_reason":"reset","next_proto_version":1,"downgrade_reason":"session_dropped"}
```

### `disconnected`

A session that connected has ended. There is exactly one for each
`connected`. A connection attempt that fails never connected and has
neither.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `disconnect_reason` | string | always | Why: see [`disconnect_reason`](#disconnect_reason) |
| `error_code` | integer | with `error_report` | The Error Report's code |
| `error_text` | string | absent on `shutdown` | RAVEN's own description of the failure, for people. It is not stable: do not parse it |

```json
{"timestamp":"2026-11-11T21:06:49.145072068Z","cache":"rtr.example.net:3323","event_type":"disconnected","schema_version":1,"error_text":"read PDU: EOF","proto_version":2,"disconnect_reason":"eof"}
{"timestamp":"2026-11-11T21:06:49.107190568Z","cache":"rtr.example.net:3323","event_type":"disconnected","schema_version":1,"error_text":"cache sent error report (code 0): Corrupt Data","error_code":0,"proto_version":2,"disconnect_reason":"error_report"}
{"timestamp":"2026-11-11T21:06:49.090477709Z","cache":"rtr.example.net:3323","event_type":"disconnected","schema_version":1,"proto_version":0,"disconnect_reason":"shutdown"}
```

### `anomaly`

The anomaly detector flagged a record: a `reset` or `error` (structural), or
an incremental `sync` whose metrics are far outside this cache's normal
(statistical). Full syncs are never evaluated. It has the flagged record's
`timestamp` and `cache`, and no `proto_version`.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `category` | string | always | `structural` or `statistical` |
| `trigger` | string | always | structural: `cache_reset` (a `reset`), `error_report` (an `error` from the cache) or `protocol_error` (an `error` with `error_origin` `client`). statistical: the metric that crossed the hard threshold, or, for a correlated trip, the metrics that crossed the soft threshold joined with `+` in the order of [the statistics](#statistics), e.g. `interval_since_ns+sync_duration_ns` |
| `severity` | string | always | `high`: every structural anomaly, and a statistical one past the hard threshold. `medium`: a correlated trip (two or more metrics past the soft threshold) |
| `z_scores` | object | statistical | For each metric at or above its soft threshold, its modified z-score (unitless; the scale is the window's MAD with a minimum spread, see the detector). Keys are [statistics](#statistics) |
| `raw` | object | statistical | Every metric's value in the flagged sync: nanoseconds for `*_ns`, counts otherwise. Keys are [statistics](#statistics) |

```json
{"timestamp":"2026-11-11T21:06:49.097425939Z","cache":"rtr.example.net:3323","event_type":"anomaly","schema_version":1,"category":"statistical","trigger":"vrp_announced","severity":"high","z_scores":{"vrp_announced":808.0509999999999},"raw":{"aspa_announced":1,"aspa_withdrawn":1,"interval_since_ns":5717680,"sync_duration_ns":1897959,"vrp_announced":1200,"vrp_withdrawn":3}}
{"timestamp":"2026-11-11T21:06:49.10142665Z","cache":"rtr.example.net:3323","event_type":"anomaly","schema_version":1,"category":"structural","trigger":"cache_reset","severity":"high"}
```

## Comparing caches

With more than one `--cache`, the monitor keeps each cache's VRP and ASPA
set apart and compares them after every End of Data from any cache. It
writes three more record types; with a single `--cache` it writes none of
them, and the rest of the output is unchanged.

**Which caches are compared:** those connected that have completed at
least one sync in their current session. A cache that disconnects leaves the
comparison and rejoins after the first sync of its next session. ASPA sets
are compared only among caches at RTR version 2; a cache at version 0 or 1
is compared on VRPs only.

**What is compared:** VRPs by prefix, maxLength and origin AS; ASPAs by
customer AS, comparing provider sets. An item some compared caches hold and
others do not (for ASPA: a customer whose provider set differs) is a
difference. It is classified by who holds it:

- held by a majority of the compared caches: **missing** at the caches
  that lack it
- held by a minority: **extra** at the caches that hold it
- no majority (two caches, or an even split): **split**, at every compared
  cache, naming both sides

For ASPA, the majority is a majority of caches holding the same provider
set; a cache in the minority with no record for the customer is
`aspa_missing`, one with a record where the majority has none `aspa_extra`,
one with a different set `aspa_mismatch`.

**The settle window:** a difference counts only once it has lasted longer
than the settle window with the same shape (the same compared caches, the
same holders), so a cache that is merely a poll behind is never reported.
The window is twice the slowest compared cache's refresh interval (the
median of its last 15 `interval_since_ns`), at least 10 minutes; until every
compared cache has an interval, it is 30 minutes. `--compare-settle`
replaces it. Differences are checked at each End of Data, so one is reported
at the first sync after it settles.

**Episodes:** a cache's persistent differences are reported per episode,
not per item: one `divergence` when its first difference settles, and one
`divergence_resolved` when it has no difference left at all (settled or
not). A cache out of the comparison keeps its episode open until it rejoins.

**Upstream changes:** a change that trips the anomaly detector (a
statistical anomaly on a VRP or ASPA count) at every compared cache within
the settle window, with the changes overlapping by at least 90% (shared
items over the larger change's items), is a change upstream of every
validator, such as a repository losing objects. It is written once, as
`upstream_change`; each cache's `anomaly` is still written. A large change
seen at one cache only is never upstream: if it lasts, it is a divergence at
that cache.

**Upstream changes need a warmed-up detector at every compared cache.** The
detector scores a sync only once it has seen 100 incremental syncs of that
cache (full syncs do not count): about 17 hours at a 10-minute refresh
interval, 8 at 5 minutes. Until every compared cache is past that, a real
upstream event is not recognised as one: it shows as an `anomaly` at the
caches that are warm and nothing at the others, never as `upstream_change`.
A baseline saved by an earlier run (`--anomaly-snapshot`) or seeded from
recorded NDJSON (`raven rtr seed-baseline`) skips the warm-up; the baseline
is kept per cache address, so it applies only to caches given by the same
`--cache` string.

**Standing divergences by design:** the comparison assumes the caches
should hold the same data. Caches that validate against different Trust
Anchor sets, or apply different local exceptions (SLURM, RFC 8416, filters
and assertions), hold different data on purpose, and the monitor reports
that difference as a divergence that never resolves: for example
`vrp_extra` at the only cache with a SLURM assertion, or `vrp_missing` at a
cache that lacks a TAL the others have. Compare caches with the same TALs
and exceptions, or expect those episodes.

**Memory:** each cache costs about 316 MB at 1M VRPs: about 236 MB for its
VRP store (which the RTR session needs with or without comparison) and
about 80 MB for the comparison's own copy of its set. The copy exists only
with more than one `--cache`; ASPA adds little at today's sizes.

### `divergence`

A cache's first persistent difference settled: a divergence episode began.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `episode` | integer | always | The episode's number at this cache, from 1, in this process |
| `started_at` | string | always | When the episode's earliest difference first appeared in its current shape (RFC 3339, UTC) |
| `compared` | array of strings | always | The caches compared, in `--cache` order |
| `settle_ns` | integer | always | The settle window in effect, in nanoseconds |
| `counts` | object | always | Persistent differences attributed to this cache, by [kind](#divergence-kind); only kinds with at least one |
| `samples` | array of objects | always | Up to 20 of those differences, taken from each kind in turn, sorted by kind and item (below) |
| `split_with` | array of strings | with a split kind | The caches on the other side of the split items |

Each sample:

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `kind` | string | always | The [kind](#divergence-kind) |
| `prefix` | string | VRP kinds | The VRP's prefix, as the cache sent it |
| `max_length` | integer | VRP kinds | The VRP's maxLength |
| `asn` | integer | VRP kinds | The VRP's origin AS |
| `customer_asn` | integer | ASPA kinds | The customer AS |
| `providers` | array of integers | ASPA kinds, when this cache has a record | This cache's provider set, sorted |
| `majority_providers` | array of integers | ASPA kinds with a majority that has a record | The majority's provider set, sorted |
| `agree` | array of strings | always | The compared caches that hold what this cache holds for the item, it included |
| `disagree` | array of strings | always | The others |

```json
{"timestamp":"2026-11-12T03:34:36.860743886Z","cache":"rtr-c.example.net:3323","event_type":"divergence","schema_version":1,"episode":1,"started_at":"2026-11-12T03:34:35.957205531Z","compared":["rtr-a.example.net:3323","rtr-b.example.net:3323","rtr-c.example.net:3323"],"settle_ns":750000000,"counts":{"aspa_mismatch":1,"aspa_missing":1,"aspa_split":1,"vrp_missing":2},"samples":[{"kind":"vrp_missing","prefix":"10.0.0.0/24","max_length":24,"asn":65001,"agree":["rtr-c.example.net:3323"],"disagree":["rtr-a.example.net:3323","rtr-b.example.net:3323"]},{"kind":"vrp_missing","prefix":"10.0.0.1/24","max_length":24,"asn":65001,"agree":["rtr-c.example.net:3323"],"disagree":["rtr-a.example.net:3323","rtr-b.example.net:3323"]},{"kind":"aspa_missing","customer_asn":64510,"majority_providers":[64511],"agree":["rtr-c.example.net:3323"],"disagree":["rtr-a.example.net:3323","rtr-b.example.net:3323"]},{"kind":"aspa_mismatch","customer_asn":64500,"providers":[64501],"majority_providers":[64501,64502],"agree":["rtr-c.example.net:3323"],"disagree":["rtr-a.example.net:3323","rtr-b.example.net:3323"]},{"kind":"aspa_split","customer_asn":64530,"providers":[3],"agree":["rtr-c.example.net:3323"],"disagree":["rtr-a.example.net:3323","rtr-b.example.net:3323"]}],"split_with":["rtr-a.example.net:3323","rtr-b.example.net:3323"]}
{"timestamp":"2026-11-12T03:34:36.830638224Z","cache":"rtr-a.example.net:3323","event_type":"divergence","schema_version":1,"episode":1,"started_at":"2026-11-12T03:34:35.928699408Z","compared":["rtr-a.example.net:3323","rtr-b.example.net:3323"],"settle_ns":750000000,"counts":{"aspa_split":1,"vrp_split":5},"samples":[{"kind":"vrp_split","prefix":"10.0.19.136/24","max_length":24,"asn":65002,"agree":["rtr-a.example.net:3323"],"disagree":["rtr-b.example.net:3323"]},{"kind":"vrp_split","prefix":"10.0.19.137/24","max_length":24,"asn":65002,"agree":["rtr-a.example.net:3323"],"disagree":["rtr-b.example.net:3323"]},{"kind":"vrp_split","prefix":"10.0.19.138/24","max_length":24,"asn":65002,"agree":["rtr-a.example.net:3323"],"disagree":["rtr-b.example.net:3323"]},{"kind":"vrp_split","prefix":"10.0.19.139/24","max_length":24,"asn":65002,"agree":["rtr-a.example.net:3323"],"disagree":["rtr-b.example.net:3323"]},{"kind":"vrp_split","prefix":"10.0.19.140/24","max_length":24,"asn":65002,"agree":["rtr-a.example.net:3323"],"disagree":["rtr-b.example.net:3323"]},{"kind":"aspa_split","customer_asn":64500,"providers":[1],"agree":["rtr-a.example.net:3323"],"disagree":["rtr-b.example.net:3323"]}],"split_with":["rtr-b.example.net:3323"]}
```

The second example compares two caches: with no majority, each gets its own
`divergence` with the same items as `vrp_split`.

### `divergence_resolved`

A divergence episode ended: the cache no longer disagrees with the other
compared caches on anything.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `episode` | integer | always | The episode that ended |
| `started_at` | string | always | The episode's `started_at` |
| `duration_ns` | integer | always | Nanoseconds from `started_at` to this record |
| `compared` | array of strings | always | The caches compared, in `--cache` order |

```json
{"timestamp":"2026-11-12T03:34:36.875279716Z","cache":"rtr-b.example.net:3323","event_type":"divergence_resolved","schema_version":1,"episode":1,"started_at":"2026-11-12T03:34:35.957205531Z","duration_ns":918074185,"compared":["rtr-a.example.net:3323","rtr-b.example.net:3323","rtr-c.example.net:3323"]}
```

### `upstream_change`

The same large change reached every compared cache within the settle
window: a change upstream of the validators. One record for the change; each
cache's `anomaly` record is written as well.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `caches` | array of strings | always | The caches the change reached: every compared cache, in `--cache` order |
| `changes` | array of objects | always | Each cache's sync that carried it, in `--cache` order: `cache`, `serial`, `timestamp`, and its `vrp_announced`, `vrp_withdrawn` and `aspa_changed` (customer ASes whose record changed) counts |
| `overlap` | number | always | The least overlap between the completing cache's change and another's: shared items over the larger change's items, 0.9 to 1 |
| `settle_ns` | integer | always | The settle window in effect, in nanoseconds |
| `samples` | array of objects | always | Up to 20 items every cache's change has, taken from each kind of change in turn: `change` ([below](#upstream-change)), and `prefix`, `max_length`, `asn` for a VRP or `customer_asn` for an ASPA |

```json
{"timestamp":"2026-11-12T03:34:36.918629637Z","cache":"rtr-c.example.net:3323","event_type":"upstream_change","schema_version":1,"caches":["rtr-a.example.net:3323","rtr-b.example.net:3323","rtr-c.example.net:3323"],"changes":[{"cache":"rtr-a.example.net:3323","serial":2,"timestamp":"2026-11-12T03:34:36.889320219Z","vrp_announced":1200,"vrp_withdrawn":3,"aspa_changed":1},{"cache":"rtr-b.example.net:3323","serial":1,"timestamp":"2026-11-12T03:34:36.903863861Z","vrp_announced":1200,"vrp_withdrawn":3,"aspa_changed":1},{"cache":"rtr-c.example.net:3323","serial":3,"timestamp":"2026-11-12T03:34:36.915758512Z","vrp_announced":1200,"vrp_withdrawn":3,"aspa_changed":1}],"overlap":1,"settle_ns":750000000,"samples":[{"change":"vrp_announced","prefix":"10.0.39.16/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.17/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.18/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.19/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.20/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.21/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.22/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.23/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.24/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.25/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.26/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.27/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.28/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.29/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.30/24","max_length":24,"asn":65004},{"change":"vrp_announced","prefix":"10.0.39.31/24","max_length":24,"asn":65004},{"change":"vrp_withdrawn","prefix":"10.0.0.10/24","max_length":24,"asn":65001},{"change":"vrp_withdrawn","prefix":"10.0.0.11/24","max_length":24,"asn":65001},{"change":"vrp_withdrawn","prefix":"10.0.0.12/24","max_length":24,"asn":65001},{"change":"aspa_changed","customer_asn":64540}]}
```

## Enums

### `disconnect_reason`

| Value | Meaning |
|---|---|
| `eof` | The cache closed the connection (FIN) |
| `reset` | The connection was reset (RST, broken pipe) |
| `error_report` | The cache sent an Error Report; `error_code` says which. Follows an `error`, a `cache_not_ready` or a `version_downgrade` |
| `timeout` | No answer within the Retry Interval, or a TCP timeout |
| `shutdown` | The monitor is stopping |
| `version_upgrade` | A re-probe found the cache now supports the version the monitor started at; it reconnects at it |
| `error` | Any other read, write or protocol failure (for example a cache answering at another version than a pinned one) |

### `downgrade_reason`

`unsupported_version`, `session_dropped`; see
[`version_downgrade`](#version_downgrade).

### `sync_type`

`full`, `incremental`.

### `reset_reason`

`cache_reset_pdu`: the only reason version 1 writes.

### `category` and `severity`

`category`: `structural`, `statistical`. `severity`: `high`, `medium`.

### Statistics

The metrics the detector scores, as keys of `z_scores` and `raw` and in
`trigger`, in this order: `interval_since_ns`, `sync_duration_ns`,
`vrp_announced`, `vrp_withdrawn`, `aspa_announced`, `aspa_withdrawn`.
`interval_since_ns` and `sync_duration_ns` are the `sync` fields of the
same names. The four counts are the sync's net change: `vrp_added`,
`vrp_removed`, `aspa_added` and `aspa_removed`, under the names they have
always had (see [PDUs received and net change](#pdus-received-and-net-change)).
A delta that duplicates records is reported as a `protocol_error`, not also
as a burst of announcements. On a correct cache's incremental sync the
values are the PDU counts, as before.

### Divergence kind

The keys of `counts`, the `kind` of a `divergence` sample, and the `kind`
label of `raven_rtr_divergent_items`, in this order. See
[Comparing caches](#comparing-caches).

| Value | Meaning |
|---|---|
| `vrp_missing` | A VRP a majority of the compared caches hold, and this cache does not |
| `vrp_extra` | A VRP this cache and a minority hold |
| `vrp_split` | A VRP held by exactly half the compared caches |
| `aspa_missing` | A customer AS this cache has no record for, where the majority has one |
| `aspa_extra` | A customer AS this cache has a record for, where the majority has none |
| `aspa_mismatch` | A customer AS whose provider set at this cache differs from the majority's |
| `aspa_split` | A customer AS on whose provider set no majority of the compared caches agrees |

### Upstream change

The `change` of an `upstream_change` sample: `vrp_announced`,
`vrp_withdrawn`, `aspa_changed` (the customer AS's record was added,
removed or changed).

## Other files

The anomaly detector's baseline (`--anomaly-snapshot`) is a separate JSON
file, not part of this contract; it is internal state and may change between
releases. `raven rtr seed-baseline` reads this NDJSON: it uses `sync` records
and ignores every other record type.
