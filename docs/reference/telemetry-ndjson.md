# Telemetry NDJSON

`raven rtr monitor` writes one JSON object per line (NDJSON) to `--log-file`:
the RTR session's lifecycle, every completed sync, and every anomaly the
detector finds. This page is the contract for that output: what each record
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
  It has that record's `timestamp` and `cache`; match on those.
- Strings are JSON-escaped by Go's encoder: `<`, `>` and `&` appear as
  `\u003c`, `\u003e`, `\u0026`. Use a JSON parser, not text matching.
- Durations are integers in nanoseconds (`*_ns`). Counts are integers.

### Fields on every record

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | `1` |
| `timestamp` | string | When the event happened: RFC 3339 with up to nanosecond precision (trailing zeros trimmed) and a UTC offset, which consumers must honor. RAVEN writes UTC (`2026-11-11T21:06:49.0886Z`) from this release; files from older releases may carry the monitor host's local offset (`2026-11-11T13:06:49.0886-08:00`) |
| `cache` | string | The RTR cache, exactly as given to `--cache` (`host:port`) |
| `event_type` | string | The record type: one of the sections below |

Every record type except `anomaly` also has:

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
they are 0.

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `sync_type` | string | always | `full` or `incremental` |
| `serial_changed` | boolean | always | The serial differs from the previous sync's, in this process, across sessions: `true` on the first sync; a full sync of a new session can be `false` |
| `serial` | integer | always, 0 included | The cache's serial from End of Data (0 to 4294967295) |
| `vrp_total` | integer | always, 0 included | VRPs held after the sync. A VRP the cache announced twice counts twice |
| `vrp_announced` | integer | always, 0 included | VRP announcement PDUs in this sync (IPv4 and IPv6). On a full sync, the whole set |
| `vrp_withdrawn` | integer | always, 0 included | VRP withdrawal PDUs in this sync |
| `aspa_total` | integer | always, 0 included | ASPA records held after the sync: customer ASes. 0 below RTR version 2 |
| `aspa_announced` | integer | always, 0 included | ASPA announcement PDUs in this sync (one per customer AS) |
| `aspa_withdrawn` | integer | always, 0 included | ASPA withdrawal PDUs in this sync |
| `sync_duration_ns` | integer | always, 0 included | Nanoseconds from sending the query to receiving End of Data |
| `interval_since_ns` | integer | absent on the first sync of the process | Nanoseconds since the previous sync's End of Data in this process, across sessions |

```json
{"timestamp":"2026-11-11T21:06:49.089760506Z","cache":"rtr.example.net:3323","event_type":"sync","schema_version":1,"sync_type":"full","serial_changed":true,"proto_version":1,"serial":0,"vrp_total":0,"vrp_announced":0,"vrp_withdrawn":0,"aspa_total":0,"aspa_announced":0,"aspa_withdrawn":0,"sync_duration_ns":318784}
{"timestamp":"2026-11-11T21:06:49.091708344Z","cache":"rtr.example.net:3323","event_type":"sync","schema_version":1,"sync_type":"full","serial_changed":true,"proto_version":2,"serial":0,"vrp_total":50,"vrp_announced":50,"vrp_withdrawn":0,"aspa_total":2,"aspa_announced":2,"aspa_withdrawn":0,"sync_duration_ns":1369810}
{"timestamp":"2026-11-11T21:06:49.097425939Z","cache":"rtr.example.net:3323","event_type":"sync","schema_version":1,"interval_since_ns":5717680,"sync_type":"incremental","serial_changed":true,"proto_version":2,"serial":1,"vrp_total":1247,"vrp_announced":1200,"vrp_withdrawn":3,"aspa_total":2,"aspa_announced":1,"aspa_withdrawn":1,"sync_duration_ns":1897959}
```

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

| Field | Type | Presence | Meaning |
|---|---|---|---|
| `error_code` | integer | always | The RFC 8210 §12 error code |
| `error_text` | string | absent when the cache sent none | The cache's error text |

```json
{"timestamp":"2026-11-11T21:06:49.107152206Z","cache":"rtr.example.net:3323","event_type":"error","schema_version":1,"error_text":"Corrupt Data","error_code":0,"proto_version":2}
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
| `trigger` | string | always | structural: `cache_reset` (a `reset`) or `error_report` (an `error`). statistical: the metric that crossed the hard threshold, or, for a correlated trip, the metrics that crossed the soft threshold joined with `+` in the order of [the statistics](#statistics), e.g. `interval_since_ns+sync_duration_ns` |
| `severity` | string | always | `high`: every structural anomaly, and a statistical one past the hard threshold. `medium`: a correlated trip (two or more metrics past the soft threshold) |
| `z_scores` | object | statistical | For each metric at or above its soft threshold, its modified z-score (unitless; the scale is the window's MAD with a minimum spread, see the detector). Keys are [statistics](#statistics) |
| `raw` | object | statistical | Every metric's value in the flagged sync: nanoseconds for `*_ns`, counts otherwise. Keys are [statistics](#statistics) |

```json
{"timestamp":"2026-11-11T21:06:49.097425939Z","cache":"rtr.example.net:3323","event_type":"anomaly","schema_version":1,"category":"statistical","trigger":"vrp_announced","severity":"high","z_scores":{"vrp_announced":808.0509999999999},"raw":{"aspa_announced":1,"aspa_withdrawn":1,"interval_since_ns":5717680,"sync_duration_ns":1897959,"vrp_announced":1200,"vrp_withdrawn":3}}
{"timestamp":"2026-11-11T21:06:49.10142665Z","cache":"rtr.example.net:3323","event_type":"anomaly","schema_version":1,"category":"structural","trigger":"cache_reset","severity":"high"}
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
`vrp_announced`, `vrp_withdrawn`, `aspa_announced`, `aspa_withdrawn`. They
are the `sync` fields of the same names.

## Other files

The anomaly detector's baseline (`--anomaly-snapshot`) is a separate JSON
file, not part of this contract; it is internal state and may change between
releases. `raven rtr seed-baseline` reads this NDJSON: it uses `sync` records
and ignores every other record type.
