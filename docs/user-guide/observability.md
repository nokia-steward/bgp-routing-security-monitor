# Observability & Metrics

RAVEN exposes a Prometheus metrics endpoint and ships with pre-built Grafana
dashboards that give you a real-time view of your routing security posture.

## Prometheus

### Enabling the Metrics Endpoint

Add to your `raven.yaml`:

```yaml
outputs:
  prometheus:
    listen: ":9595"
    path: "/metrics"
```

Verify it is working:

```bash
curl http://localhost:9595/metrics | grep raven
```

### Prometheus Scrape Configuration

Add RAVEN to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: raven
    static_configs:
      - targets: ["localhost:9595"]
    scrape_interval: 15s
```

!!! note
    If RAVEN is running in a container or WSL and Prometheus is running in Docker, use the Docker bridge gateway IP instead of localhost. Typically `172.17.0.1` on Linux.

    ```yaml
    static_configs:
      - targets: ["172.17.0.1:9595"]
    ```

### Available Metrics

**Route counts by security posture and RIB:**

```text
raven_routes_total{posture="secured", afi="ipv4", rib="adj-rib-in-pre"}
raven_routes_total{posture="origin-only", afi="ipv4", rib="adj-rib-in-pre"}
raven_routes_total{posture="path-suspect", afi="ipv4", rib="adj-rib-in-pre"}
raven_routes_total{posture="path-only", afi="ipv4", rib="adj-rib-in-pre"}
raven_routes_total{posture="unverified", afi="ipv4", rib="adj-rib-in-pre"}
raven_routes_total{posture="origin-invalid", afi="ipv4", rib="adj-rib-in-pre"}
```

Same metrics available with `afi="ipv6"`, and with `rib="adj-rib-in-post"`
and `rib="loc-rib"`. Every combination of `posture`, `afi` and `rib` is
exported, at 0 when it has no routes.

`raven_routes_total` counts the routes your routers received (Adj-RIB-In
pre-policy and post-policy) and selected (Loc-RIB), each RIB under its own
`rib` label. A router that sends two RIBs reports most of its routes in
both, so a sum over every RIB counts those routes twice: always filter on
`rib`. Routes your routers send are counted separately (see
[Adj-RIB-Out routes](#adj-rib-out-routes)), so `raven_routes_total` never
mixes the two directions.

**Route table size by RIB:**

```text
raven_route_table_size{rib="adj-rib-in-pre"}     # Routes in the table, one series per RIB
raven_route_table_size{rib="adj-rib-in-post"}
raven_route_table_size{rib="loc-rib"}
```

!!! warning "Breaking change: rib label on raven_routes_total and raven_route_table_size"
    Both metrics gained a `rib` label. They used to count Adj-RIB-In
    pre-policy routes only, without the label, so a router that sent only
    its Loc-RIB showed 0 routes. A query without a `rib` matcher now adds
    up the RIBs, counting a route once per RIB it is reported in. To keep
    the old values, add `rib="adj-rib-in-pre"`:

    ```promql
    sum by (posture) (raven_routes_total{rib="adj-rib-in-pre"})
    raven_route_table_size{rib="adj-rib-in-pre"}
    ```

    To count what route queries return (the
    [default view](../getting-started/concepts.md#which-rib-to-monitor),
    Adj-RIB-In pre-policy and Loc-RIB), as `raven status` does:

    ```promql
    sum(raven_route_table_size{rib=~"adj-rib-in-pre|loc-rib"})
    ```

    To keep pre-upgrade history visible, match an empty `rib` too
    (`rib=~"adj-rib-in-pre|"`, or `rib=~"adj-rib-in-pre|loc-rib|"` for the
    default view), since series from before the upgrade have no `rib` label.

    The Grafana dashboard in the code repository
    (`lab/grafana-dashboard.json`) uses these queries. The OpenTelemetry
    gauge `raven.routes.total` has the same `rib` attribute.

**BMP session health:**

```text
raven_bmp_session_state{router="edge1"}                                   # 1=up, 0=down
raven_bmp_messages_total{router="edge1", msg_type="route_monitoring"}
raven_bmp_peer_state{router="edge1", router_addr="192.0.2.1", peer="198.51.100.1", peer_distinguisher=""}   # 1=established, 0=down
```

`router` is the router's BMP sysName, or its address when it sent none. A
router's Loc-RIB instance has its own `raven_bmp_peer_state` series, with
`peer="0.0.0.0"` (the zero address RFC 9069 gives it) and the instance's
route distinguisher, `""` for the default instance.

`raven_bmp_peer_state` goes to 0 for a peer on its Peer Down, and for every
peer of a BMP session when that session ends. Earlier releases left it at
1 after the session ended for peers that had no Peer Down first, until
RAVEN restarted.

!!! warning "Label change on raven_bmp_peer_state"
    `raven_bmp_peer_state` gained two labels: `router_addr`, the source
    address of the router's BMP session, and `peer_distinguisher`, the
    peer's VRF route distinguisher (`""` for a peer in the global instance,
    for example `65000:100` for one in a VRF). The same peer address on two
    routers, or in two VRFs of one router, is now two series instead of one
    series that both overwrote. Dashboards and alerts that aggregate this
    metric with `by (router, peer)` keep working but merge VRFs; add
    `peer_distinguisher` to the grouping to keep them apart. Recording rules
    that match on the exact label set need updating.

**RTR cache health:**

```text
raven_rtr_session_state{cache="localhost:3323"}               # 1=connected, 0=disconnected
raven_rtr_vrp_count{cache="localhost:3323"}                   # VRPs loaded
raven_rtr_aspa_count{cache="localhost:3323"}                  # ASPA records loaded
raven_rtr_last_sync_seconds{cache="localhost:3323"}           # Unix time of the last completed sync (End of Data)
raven_rtr_last_serial_change_seconds{cache="localhost:3323"}  # Unix time of the last sync that changed the serial
raven_rtr_data_expired{cache="localhost:3323"}                # 1 if no sync completed within the Expire Interval
raven_rtr_protocol_version{cache="localhost:3323"}            # Negotiated RTR version (ASPA needs 2)
raven_rtr_disconnects_total{cache="localhost:3323", reason="eof"}  # RTR sessions that ended, by reason
```

`reason` is the same set `raven rtr monitor` writes as `disconnect_reason`:
`eof` (the cache closed the connection), `reset` (connection reset),
`error_report` (the cache sent an Error Report), `timeout` (no answer within
the Retry Interval, or a TCP timeout), `shutdown`, `version_upgrade` (a
re-probe found the configured version) and `error` (any other failure).
The OpenTelemetry gauge `raven.rtr.session.state` now drops to 0 as soon as a
session ends, as `raven_rtr_session_state` already did; it used to stay 1
until the client stopped.

**Route changes and watch:**

```text
raven_route_posture_changes_total{source="rtr", from="origin-only", to="origin-invalid"}
raven_watch_events_dropped_total                              # watch events dropped: a watcher not reading fast enough
raven_events_rtr_bulk_changes_total                           # RTR updates reported as one rtr_bulk_change event
raven_events_rtr_bulk_suppressed_actions_total                # per-route event actions the bulk guard did not run
```

`raven_route_posture_changes_total` counts posture transitions of routes
already in the table, by what caused them: `bmp` (an announcement) or `rtr`
(revalidation after an RTR update). A new route is not a transition. A
`raven watch` client that stops reading loses events once its buffer (1024
events) is full; each one counts in `raven_watch_events_dropped_total`, and
RAVEN logs once when a watcher starts dropping and once when it catches up.
See [RTR bulk guard](configuration.md#rtr-bulk-guard) for the bulk metrics.

#### ASPA verification

```text
raven_aspa_validations_total{procedure="upstream", source="config-asn", state="Invalid"}
```

A counter of ASPA verifications, incremented each time RAVEN verifies a
route: on ingest and again on every revalidation pass. Labels:

| Label | Values |
|---|---|
| `procedure` | `upstream`, `downstream` |
| `source` | `default`, `config-address`, `config-asn`: where the procedure came from (see [`validation.aspa-peers`](configuration.md#validationaspa-peers)) |
| `state` | `Valid`, `Invalid`, `Unknown`, `Unverifiable` |

Use it to confirm your `aspa-peers` mapping took effect, and to see which
procedure produces your `Invalid` results. A jump in
`procedure="upstream", source="default", state="Invalid"` after a new
transit session comes up usually means a provider is missing from
`aspa-peers` and is being verified with the wrong procedure. Adj-RIB-Out
routes are not ASPA-verified and are not counted. Nor is any route while
ASPA verification is off: until an RTR cache syncs at protocol version 2,
or with `validation.aspa: false` (see
[ASPA without ASPA data](../architecture/validation-engine.md#aspa-without-aspa-data)).
Loc-RIB routes are counted with `source="config-asn"` or
`source="default"`, never `config-address`. Because revalidation
counts too, read the rate, not the absolute value:

```promql
sum by (procedure, source, state) (rate(raven_aspa_validations_total[5m]))
```

#### Revalidation

When an RTR sync changes VRPs or ASPA records, RAVEN revalidates the routes
the change can affect (see
[Validation Engine](../architecture/validation-engine.md#incremental-revalidation)).

```text
raven_revalidation_duration_seconds{mode="incremental"}            # Histogram: wall time of each pass
raven_revalidation_routes_total{mode="incremental", result="checked"}
raven_revalidation_routes_total{mode="incremental", result="changed"}
```

`mode` is `incremental` for a pass driven by an RTR delta and `full` for a
pass over the whole table, which happens after a Cache Reset, a new RTR
session or a session-ID change. `result="checked"` counts routes
revalidated; `result="changed"` counts those whose ROV, ASPA or posture
result changed. The duration is wall time from start to finish, and the
pass is interleaved with BMP ingest, so it is not time ingest was blocked.

Watch these to catch revalidation falling behind. An incremental pass
touches only the routes the delta can affect, so it should be far shorter
than a full pass; a run of `full` passes means the cache keeps resetting the
session. Each pass also logs `re-validation complete` with `mode`,
`candidates`, `checked`, `changed` and `took`.

```promql
histogram_quantile(0.95, sum by (le, mode) (rate(raven_revalidation_duration_seconds_bucket[1h])))
```

#### BMP ingest health

```text
raven_bmp_rejected_connections_total{reason="not_allowed"}       # Source outside bmp.allowed-routers
raven_bmp_rejected_connections_total{reason="bad_remote_addr"}   # Source address could not be read
raven_bmp_unsupported_nlri_total{afi="25", safi="70"}            # MP_REACH/MP_UNREACH not decoded, by AFI/SAFI
```

`raven_bmp_rejected_connections_total` counts BMP connections RAVEN closed
at accept, before reading anything, because of
[`bmp.allowed-routers`](configuration.md#bmp-section). Any increase means
something other than your routers reached the BMP port; check the WARN log
line `BMP connection rejected` for the source address. It stays at 0 when
`allowed-routers` is empty, because nothing is rejected.

`raven_bmp_unsupported_nlri_total` counts MP_REACH_NLRI and MP_UNREACH_NLRI
attributes for address families RAVEN does not decode, anything other than
IPv4 and IPv6 unicast (for example, L2VPN EVPN is AFI 25, SAFI 70). Those
routes are not in the route table. A steady rate tells you a router is
sending address families you may want to stop exporting over BMP; RAVEN
counts them so they are not dropped silently. `afi` and `safi` are decimal.

#### Malformed UPDATEs

```text
raven_bmp_malformed_updates_total{action="treat_as_withdraw", reason="origin"}
```

A counter of malformed BGP UPDATEs received over BMP, which RAVEN handles
under RFC 7606 the way your router does (see
[Malformed BGP Input](../troubleshooting.md#malformed-bgp-input)). Labels:

| Label | Values |
|---|---|
| `action` | The strongest RFC 7606 class the UPDATE's errors call for: `attribute_discard`, `treat_as_withdraw` or `session_reset` |
| `reason` | The error that called for it: `as_path`, `attr_length`, `attr_flags`, `origin`, `next_hop`, `med`, `local_pref`, `communities`, `originator_id`, `cluster_list`, `large_communities`, `missing_mandatory`, `as4_path`, `as4_aggregator`, `duplicate_attr`, `nlri`, `mp_reach`, `mp_reach_next_hop`, `mp_unreach`, `duplicate_mp` or `update_length` |

`attribute_discard` carries only `as4_path`, `as4_aggregator` and
`duplicate_attr`. `session_reset` carries `nlri`, `mp_reach`,
`mp_reach_next_hop`, `mp_unreach`, `duplicate_mp`, `update_length`, and any
attribute reason found in an UPDATE that announces no prefixes. Each
malformed UPDATE counts once, under its strongest error.

On a healthy network this stays at 0. Alert on any `session_reset`: it
means a peer sent something your router answers by resetting the BGP
session, and RAVEN's view of that peer may be incomplete until the session
comes back.

```promql
sum by (action, reason) (increase(raven_bmp_malformed_updates_total[1h]))
```

#### Adj-RIB-Out routes

```text
raven_adj_rib_out_routes_total{posture="origin-only", afi="ipv4"}
```

The number of Adj-RIB-Out pre-policy routes (RFC 8671): what your routers
send their peers, before outbound policy, by posture and address family.
It is kept apart from `raven_routes_total` so that received and sent routes
never add up into one number. Adj-RIB-Out routes get ROV only; their ASPA
state is always `Unverifiable`, because ASPA verification applies to routes
received from a neighbor. Use it to spot `origin-invalid` routes your
network is advertising.

#### Zero-valued series at startup

These metrics export every label combination at 0 from
startup, so an alert can tell "none yet" from "not exported":
`raven_routes_total` and `raven_route_table_size` (every `rib`),
`raven_bmp_rejected_connections_total`, `raven_revalidation_duration_seconds`,
`raven_revalidation_routes_total`, `raven_aspa_validations_total`,
`raven_bmp_malformed_updates_total` (every action and reason pair it can
carry), `raven_route_posture_changes_total` (every source and posture pair),
`raven_rtr_disconnects_total` (every reason, per configured cache), the
`raven_global_check_*` counters once a provider is enabled, and
`raven_rtr_anomaly_total` per cache in `raven rtr monitor`.
`raven_bmp_unsupported_nlri_total` appears only once an unsupported family
arrives, because its label values are not known in advance.

**RTR anomaly detection:**

Emitted by the adaptive anomaly detector in `raven rtr monitor` when it is run
with `--prometheus`. `severity` is `high` or `medium`. See
[CLI Reference → raven rtr monitor](cli-reference.md#raven-rtr-monitor).

```text
raven_rtr_anomaly_total{cache="localhost:3323", severity="high"}     # Count of anomalies, by severity
raven_rtr_anomaly_last_timestamp{cache="localhost:3323"}             # Unix timestamp of most recent anomaly
```

**RTR cache comparison:**

Emitted by `raven rtr monitor` run with several `--cache` and
`--prometheus`: per cache and
[divergence kind](../reference/telemetry-ndjson.md#divergence-kind), the
items (VRPs, ASPA customer ASes) the cache has disagreed with the other
compared caches on for longer than the settle window; and whether the cache
is in the comparison at all. Both are exported at 0 for every cache (and
kind) from startup. Neither is exported with a single `--cache`.

```text
raven_rtr_divergent_items{cache="fort.example.net:323", kind="vrp_missing"}   # Persistent differences attributed to the cache
raven_rtr_compared{cache="fort.example.net:323"}                              # 1 while in the comparison, 0 otherwise
```

`raven_rtr_compared` is 1 while the cache is connected and has completed a
sync in its current session, and 0 otherwise: from startup until its first
sync, and from a disconnect until the first sync of its next session.

**`raven_rtr_divergent_items` keeps its last values while a cache is out of
the comparison** (`raven_rtr_compared` 0): a disconnected cache is not
compared, so its count is neither updated nor reset until it rejoins. Join
the two so an alert speaks only of caches compared now:

```yaml
- alert: RTRCacheDiverges
  expr: |
    (sum by (cache) (raven_rtr_divergent_items) > 0)
      and on (cache) (raven_rtr_compared == 1)
  for: 5m
  annotations:
    summary: "RTR cache {{ $labels.cache }} persistently disagrees with the other caches"
```

The settle window already delays a divergence past normal lag, so `for`
only needs to cover scrape jitter. Alert on `raven_rtr_compared == 0`
separately if a cache dropping out of the comparison matters on its own.

**External global-visibility correlation:**

Emitted when the Event Engine's `global-correlate` action runs, which requires
`external.ripestat.enabled: true`. `result` is the consensus verdict:
`match`, `divergent`, `local_only` or `inconclusive`. See
[Configuration → External Correlation](configuration.md#external-correlation-ripestat).

```text
raven_global_check_total{source="ripestat", result="match"}          # Count of correlations, by source and verdict
raven_global_check_latency_seconds                                   # Histogram of correlation latency (live lookups only)
raven_global_check_cache_hits_total{source="ripestat"}               # Correlations served from the in-process cache
raven_global_check_rate_limited_total{source="ripestat"}             # Lookups suppressed by the local rate limiter
```

When a provider is enabled, RAVEN exports every `result` series of
`raven_global_check_total`, and the cache-hit and rate-limited counters, at
0 from startup, so a series exists before the first correlation.

`raven_global_check_latency_seconds` covers only correlations that actually
went to the provider. Cache hits and rate-limited lookups make no network
round-trip, so their near-zero timings are excluded — otherwise a warm cache
would pull p50/p95 toward zero and mask the provider latency degradation you
would want to alert on. Those two are counted on
`raven_global_check_cache_hits_total` and
`raven_global_check_rate_limited_total` instead, so the activity stays
visible.

A rate-limited lookup is a local policy decision, not a failure, so it does
not appear on `raven_global_check_total` at all. A cache hit does: it
produced a real verdict.

Cache hit ratio:

```promql
rate(raven_global_check_cache_hits_total[5m])
/
rate(raven_global_check_total[5m])
```

!!! note
    `raven check global` runs in its own short-lived CLI process, so its
    correlations are never scraped. These metrics reflect daemon-side
    correlations only.

### Useful PromQL Queries

Each query names one RIB, so a route a router reports in two RIBs is
counted once. Use `rib="loc-rib"` instead for routers that send only their
Loc-RIB.

**Percentage of received IPv4 routes that are origin-invalid:**

```promql
sum(raven_routes_total{posture="origin-invalid", afi="ipv4", rib="adj-rib-in-pre"})
/
sum(raven_routes_total{afi="ipv4", rib="adj-rib-in-pre"}) * 100
```

**Alert: origin-invalid routes above threshold:**

```yaml
groups:
  - name: raven
    rules:
      - alert: RAVENOriginInvalidHigh
        expr: sum(raven_routes_total{posture="origin-invalid", rib="adj-rib-in-pre"}) > 100
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High number of origin-invalid routes detected"

      - alert: RAVENPathSuspect
        expr: sum(raven_routes_total{posture="path-suspect", rib="adj-rib-in-pre"}) > 0
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Path-suspect routes detected — possible route leak"

      - alert: RAVENRTRDataExpired
        expr: raven_rtr_data_expired == 1
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "RAVEN RTR data has expired — RPKI validation may be outdated"

      - alert: RAVENBMPRejectedConnection
        expr: increase(raven_bmp_rejected_connections_total{reason="not_allowed"}[10m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "A source outside bmp.allowed-routers tried to open a BMP session"

      - alert: RAVENBMPSessionDown
        expr: raven_bmp_session_state == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "RAVEN BMP session is down"

      - alert: RAVENRTRAnomaly
        expr: increase(raven_rtr_anomaly_total{severity="high"}[10m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "RAVEN detected a high-severity RTR sync anomaly"

      - alert: RAVENGlobalDivergence
        expr: increase(raven_global_check_total{result="divergent"}[10m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Global BGP view disagrees with RAVEN's local origin — likely a propagated hijack"

      - alert: RAVENGlobalCheckInconclusive
        expr: |
          increase(raven_global_check_total{result="inconclusive"}[30m])
          /
          increase(raven_global_check_total[30m]) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "More than half of global-visibility correlations are failing — check RIPEstat reachability"
```

**Global correlation verdict rate:**

```promql
sum by (result) (increase(raven_global_check_total[1h]))
```

A high `local_only` rate is worth investigating on its own: those prefixes
exist in your RIB but no route collector carries them, which points at leaks
or misconfiguration rather than hijacks.

## Grafana

### Importing the Pre-built Dashboard

RAVEN ships with a Grafana dashboard in the repository at
`lab/grafana-dashboard.json`.

**Via Grafana UI:**

1. Go to **Dashboards → Import**
2. Click **Upload JSON file**
3. Select `lab/grafana-dashboard.json` from the RAVEN repository
4. Set the Prometheus datasource
5. Click **Import**

**Via Grafana API:**

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d @lab/grafana-dashboard.json \
  http://admin:admin@localhost:3000/api/dashboards/import
```

### Dashboard Panels

The pre-built dashboard includes:

**Security Posture Overview**

- Route count by posture (time series) — watch for spikes in origin-invalid
- Posture distribution (pie chart) — your network's overall security health
- Origin-invalid routes table — prefix, peer, origin ASN, matched VRP
- Path-suspect routes table — prefix, peer, AS_PATH, failing hop

**RTR Cache Health**

- VRP count over time — should be stable, drops indicate validator issues
- ASPA count over time
- Cache sync latency
- Session state — alert panel turns red if cache goes down

**RTR Anomaly Detection**

- Total RTR Anomalies — `raven_rtr_anomaly_total`, broken down by severity
- Time Since Last Anomaly — driven by `raven_rtr_anomaly_last_timestamp`

**BMP Session Health**

- Messages per second by router
- Route count per peer
- Session up/down events

**Global BGP Visibility Correlation**

The last row on the dashboard, after RTR Anomaly Detection. It is fed by the
Event Engine's `global-correlate` action, so it stays empty until
`external.ripestat.enabled: true` and a rule using that action fires. See
[Configuration → External Correlation](configuration.md#external-correlation-ripestat).

- Global Consensus Results — `rate(raven_global_check_total[5m])` by
  `result`. Colour-matched to the security posture palette: match green,
  divergent red, local_only amber, inconclusive grey.
- Global Consensus — Current Totals — one stat per verdict, straight off the
  `raven_global_check_total` counters. Reads `0` rather than "No data" before
  the first correlation runs, so a verdict appearing is visible as a change.
- RIPEstat Query Performance — cache hits
  (`raven_global_check_cache_hits_total`), rate-limited calls
  (`raven_global_check_rate_limited_total`) and live queries
  (`raven_global_check_latency_seconds_count`) on one graph. This is the
  panel to watch when tuning `cache-ttl` and `rate-limit-per-min`: rising
  rate-limited calls mean the budget is too tight for your event volume.
- RIPEstat Query Latency p50/p95 — quantiles over
  `raven_global_check_latency_seconds`, in seconds. A p95 spike means
  RIPEstat is slow or unreachable, not that RAVEN is busy.

This row answers the question the posture panels cannot. When a prefix turns
up as origin-invalid, the verdict here tells you how far the announcement
actually spread. `local_only` ticking up on Current Totals means no route
collector carries the prefix at all — the announcement never left your
network, which points at a leak, a misconfiguration or a lab injection rather
than a hijack the internet has accepted. `divergent` is the opposite and the
more serious reading: the world sees a different origin than you do, so the
bogus announcement has propagated. Global Consensus Results shows the same
verdict as a rate over time, so you can see when it started.

!!! note
    The latency panels deliberately do not filter by `{source="ripestat"}`.
    `raven_global_check_latency_seconds` is registered as a plain histogram
    rather than a histogram vector, so it carries no `source` label — adding
    the matcher would select no series and leave both panels empty.

!!! tip
    `lab/demo-master.sh setup` imports the dashboard through the Grafana API
    with `overwrite: true`, so the demo lab picks this row up automatically —
    no manual import step. See [Lab → Overview](../lab/overview.md).

### Running Grafana with Docker

For the demo lab or a quick local setup:

```bash
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -e GF_SECURITY_ADMIN_PASSWORD=admin \
  grafana/grafana:latest
```

Then import the dashboard as described above and point the Prometheus
datasource at your RAVEN metrics endpoint.

## Memory Profiling (pprof)

RAVEN can expose Go's runtime profiler for diagnosing memory growth, CPU hot
spots or goroutine leaks on a running daemon. It is **off by default** and
runs on its own listener, separate from the API server and the Prometheus
endpoint.

### Enabling the pprof Endpoint

Add to your `raven.yaml` and restart RAVEN:

```yaml
debug:
  pprof:
    listen: "localhost:6060"   # empty or absent = disabled (default)
```

RAVEN logs `pprof endpoint started` with the bound address when it is up.
An idle endpoint costs nothing: profiling work happens only while a profile
is being requested, and a CPU profile adds a few percent of overhead for
the seconds it runs.

!!! warning
    Keep pprof on loopback. The endpoint is unauthenticated, and heap
    profiles expose process memory contents. If the listen address binds
    anything other than `127.x` or `::1` (including `:6060`, which binds
    every interface), RAVEN logs a warning at startup. To profile a remote
    host, leave it on `localhost` and tunnel in:
    `ssh -L 6060:localhost:6060 raven-host`.

### Diagnosing Memory Growth

**Live heap — what is holding memory right now:**

```bash
go tool pprof http://localhost:6060/debug/pprof/heap
```

At the `(pprof)` prompt, `top` ranks functions by in-use memory and `list
<func>` shows the allocating lines. To find what is *growing*, save a heap
profile now and another a few hours later, then diff them:

```bash
curl -s -o heap-1.pb.gz http://localhost:6060/debug/pprof/heap
# ...hours later...
curl -s -o heap-2.pb.gz http://localhost:6060/debug/pprof/heap
go tool pprof -base heap-1.pb.gz heap-2.pb.gz
```

**Allocations since start — what is churning memory:**

```bash
go tool pprof http://localhost:6060/debug/pprof/allocs
```

This counts every allocation since the process started, including memory
already freed. High churn with flat in-use memory points at GC pressure
rather than a leak.

**Goroutines — whether something is accumulating:**

```bash
curl -s http://localhost:6060/debug/pprof/goroutine?debug=1
```

Goroutines are grouped by identical stack, with a count for each. A count
that keeps climbing between runs, for example per-session or per-subscriber
goroutines outliving their peer, is a leak in its own right. Each leaked
goroutine also pins whatever memory it references.

!!! note
    RSS reported by the OS can sit well above the Go heap in use: the
    runtime returns freed memory to the OS lazily. Compare the heap
    profile's in-use total against `go_memstats_heap_inuse_bytes` on the
    Prometheus endpoint before concluding that memory is leaking outside the
    heap.

Other endpoints follow the standard Go layout: `/debug/pprof/` lists every
profile, `/debug/pprof/profile?seconds=30` is a CPU profile, and
`/debug/pprof/trace?seconds=5` is an execution trace. Delta profiles
(`?seconds=` on heap or allocs) are not supported; use `-base` as shown above.
