# Configuration

RAVEN is configured via a YAML file. Every section is optional — RAVEN uses
sensible defaults for anything not specified.

## Minimal Configuration

```yaml
bmp:
  listen: ":11019"

rtr:
  caches:
    - address: "localhost:3323"
```

This is enough to get RAVEN running — BMP listener on port 11019, RTR
connecting to a local Routinator instance.

## Full Configuration Reference

```yaml
# raven.yaml

bmp:
  listen: ":11019"                  # BMP listener address (default: :11019)
  allowed-routers:                  # accept BMP only from these sources (default: any)
    - 192.0.2.10
    - 198.51.100.0/28
    - 2001:db8:100::1

api:
  listen: "127.0.0.1:11020"         # API for the raven CLI (default: 127.0.0.1:11020)

rtr:
  caches:
    - address: "rpki1.example.com:3323"
      preference: 1                 # Lower = higher preference
      transport: tcp                # tcp | tls
    - address: "rpki2.example.com:3323"
      preference: 2
      transport: tls
      tls:
        ca: "/etc/raven/rpki-ca.pem"
        tls-min-version: "1.2"      # 1.2 (default) | 1.3
  rtr-version: auto                 # auto | 0 | 1 | 2: highest version to try (default: auto, i.e. 2)
  expire-interval: 7200             # Override every cache's Expire Interval (600-172800 s; default: the cache's own)

validation:
  rov: true                         # Enable ROV annotation (default: true)
  aspa: true                        # Enable ASPA annotation (default: true)
  aspa-default-procedure: upstream  # upstream (default) | downstream | auto
  aspa-as-set-behavior: unverifiable # unverifiable | best-effort
  aspa-peers:                       # per-peer ASPA procedure (default: none)
    - address: 192.0.2.1
      neighbor-role: provider       # provider | customer | peer | rs | rs-client
    - asn: 64500
      neighbor-role: customer

outputs:
  prometheus:
    listen: ":9595"                 # Prometheus metrics endpoint
    path: "/metrics"
  otel:                             # optional OTLP export (see below)
    enabled: false

external:                           # optional third-party correlation (see below)
  ripestat:
    enabled: false
  # kafka:                          # optional event sink
  #   brokers: ["localhost:9092"]
  #   topic: "raven-events"
  # file:                           # optional event sink
  #   path: "/var/log/raven/events.ndjson"

logging:
  level: info                       # debug | info | warn | error
  format: text                      # text | json

debug:
  pprof:
    listen: ""                      # e.g. "localhost:6060"; empty = disabled (default)
```

Before you expose RAVEN beyond the monitoring host, read
[Deployment Hardening](../deployment/hardening.md).

## Configuration Options Explained

### BMP Section

**`bmp.listen`** — The address and port RAVEN listens on for incoming BMP
sessions from routers. Use `0.0.0.0:11019` to listen on all interfaces,
or `192.0.2.10:11019` to bind to a specific interface.

!!! warning
    The BMP listener is unauthenticated TCP. It should be reachable only from
    your routers, never from the internet. Set `bmp.allowed-routers` and
    filter the port in your host firewall; see
    [Deployment Hardening](../deployment/hardening.md#restrict-bmp-sources).

<a id="bmpallowed-routers"></a>
**`bmp.allowed-routers`** — The sources RAVEN accepts BMP connections from.
Each entry is an IP address (a single router) or a prefix, IPv4 or IPv6:

```yaml
bmp:
  allowed-routers:
    - 192.0.2.10
    - 198.51.100.0/28
    - 2001:db8:100::1
```

RAVEN checks the source address as soon as it accepts a connection, before
it reads a byte or starts a TLS handshake. A connection from any other
source is closed, logged at WARN (`BMP connection rejected: source not in
bmp.allowed-routers`) and counted in
[`raven_bmp_rejected_connections_total`](observability.md#bmp-ingest-health).
Checking at accept means an unlisted source never reaches the BMP decoder
and never makes RAVEN do TLS work on its behalf.

- An IPv4 router that connects to a dual-stack listener arrives as an
  IPv4-mapped IPv6 address. RAVEN matches it against your IPv4 entries, so
  list routers by their IPv4 address. An IPv4-mapped entry
  (`::ffff:192.0.2.10`) is read as IPv4, and an IPv4-mapped prefix must be
  /96 or longer.
- Host bits in a prefix are ignored: `198.51.100.5/28` means
  `198.51.100.0/28`.
- Hostnames and zoned addresses (`fe80::1%eth0`) are not accepted.
- RAVEN refuses to start when an entry cannot be parsed, and the error names
  it, for example `bmp.allowed-routers[1]: "router-2" is not an IP address
  or prefix`.
- Empty or absent (the default) accepts BMP from any source. RAVEN then logs
  a startup WARN if the listener is not on a loopback address, because
  anything that can reach the port can feed routes into your route table.

### RTR Section

**`rtr.caches`** — List of RPKI validators to connect to. RAVEN connects to
all configured caches and uses the one with the lowest preference number as
primary. If the primary fails, it falls back to the next.

**`rtr.rtr-version`** — The highest RTR protocol version to try. RAVEN
opens each cache's session at this version and falls back to lower ones
when the validator does not support it: on Error Report code 4
(Unsupported Protocol Version), or when the validator closes the
connection before answering. It then re-probes this version every
`rtr.version-reprobe-interval` (default one hour) and moves back up once
the validator supports it. RTR v2 gives ASPA data; v1 and v0 give VRPs
only.

- `auto` (default) — Try version 2, the same as `2`.
- `2` — Try version 2, falling back to 1, then 0.
- `1` — Try version 1, falling back to 0. Never asks for version 2, so no
  ASPA data.
- `0` — Version 0 only (VRPs only, no ASPA, no End of Data timing).

No value of `rtr.rtr-version` pins the version: `serve` always falls back.
`raven rtr monitor --rtr-version 0|1|2` is different: it pins the session
to that version, with no fallback and no re-probe (see the
[CLI reference](cli-reference.md#raven-rtr-monitor)).

**`rtr.expire-interval`** — Overrides the Expire Interval, in seconds, for
every RTR cache. The Expire Interval is how long RPKI data from a cache
stays usable without a successful sync; once it passes,
`raven_rtr_data_expired` goes to 1 (RAVEN keeps validating with the data it
has). Without this key, or with 0, RAVEN uses the interval each cache sends
in its End of Data PDU, or 7200 seconds if the cache sends none.

Set it when you want the expiry alert on your own schedule rather than your
validator's, for example a shorter interval so that a stalled cache alerts
sooner. RFC 8210 limits the Expire Interval to 600–172800 seconds, so
RAVEN clamps a value outside that range to the nearest limit.

At startup RAVEN logs which interval applies:

```json
{"time":"2026-10-18T23:45:08.703251144-04:00","level":"INFO","msg":"RTR expire interval: each cache's own (End of Data)","expire_interval":"cache"}
```

```json
{"time":"2026-10-18T23:45:12.674034682-04:00","level":"INFO","msg":"RTR expire interval: rtr.expire-interval overrides each cache's","expire_interval":3600}
```

and, for `expire-interval: 300`:

```json
{"time":"2026-10-18T23:45:15.651935592-04:00","level":"WARN","msg":"rtr.expire-interval outside RFC 8210's 600-172800 s; clamped","configured":300,"expire_interval":600}
```

Each `RTR sync complete` log line also reports the cache's own value
(`expire`) beside the one in effect (`expire_effective`).

### Validation Section

RAVEN picks the ASPA verification procedure for each route from the BMP
peer that sent it: an `aspa-peers` entry for the peer's address first, then
one for the peer's ASN, then `aspa-default-procedure`. See
[ASPA Path Verification](../getting-started/concepts.md#upstream-and-downstream-verification)
for what the two procedures check and why the choice matters.

**`validation.aspa`** — With `true` (the default), RAVEN verifies ASPA once
an RTR cache has synced at protocol version 2, the first with ASPA data;
until then every route's ASPA state is `Unknown` with the reason
`no ASPA data (no RTR v2 session)`. With `false`, RAVEN never verifies
ASPA, and every route's ASPA state is `Unknown` with the reason
`ASPA disabled`; earlier releases ignored the setting. See
[ASPA without ASPA data](../architecture/validation-engine.md#aspa-without-aspa-data).

<a id="validationaspa-peers"></a>
**`validation.aspa-peers`** — Maps BMP peers to the neighbor's role, which
selects the procedure for routes learned from that peer. The role is what
the neighbor is to your monitored router:

| `neighbor-role` | The neighbor is your... | Procedure |
|---|---|---|
| `provider` | transit provider | `downstream` |
| `customer` | customer | `upstream` |
| `peer` | lateral (settlement-free) peer | `upstream` |
| `rs` | route server at an exchange | `upstream`, without the neighbor-AS check |
| `rs-client` | route-server client (you operate the route server) | `upstream` |

```yaml
validation:
  aspa-peers:
    - address: 192.0.2.1            # one session to a transit provider
      neighbor-role: provider
    - asn: 64500                    # every session with this customer AS
      neighbor-role: customer
    - address: 2001:db8::6777       # the exchange's route server
      neighbor-role: rs
```

Each entry sets exactly one of `address` (the BMP peer address) or `asn`
(the peer's ASN). An address entry wins over an ASN entry for the same peer,
so you can map a whole AS by ASN and override one session by address. An
`address` entry matches that peer address on every monitored router. RAVEN
refuses to start on an entry with both or neither of `address` and `asn`, an
unknown role, an unparseable address, or a repeated address or ASN.

For every peer an entry maps, except `rs`, RAVEN also runs the draft's
neighbor-AS check: the first AS in the AS_PATH must be the peer's ASN, or
the route is ASPA `Invalid` with the reason in `aspa_reason`. A route server
is left out because it does not add its own AS to the AS_PATH, so the check
would fail on every route it sends. RAVEN skips the check for routes with an
empty AS_PATH or an unknown peer ASN.

Loc-RIB routes (BMP peer type 3, RFC 9069) have no neighbor address: their
procedure comes from an `asn` entry for the neighbor AS, the first AS of
the AS_PATH, then `aspa-default-procedure`. `address` entries never match
them, and the neighbor-AS check does not apply. A leading copy of the
router's own AS, which FRR 10.2 puts in Loc-RIB paths, is removed first.
For a best path learned over iBGP, the first AS is the neighbor of the
border router that learned the route, not of the monitored router. See
[ASPA on Loc-RIB routes](loc-rib.md#aspa-on-loc-rib-routes).

RAVEN reads `aspa-peers` once at startup; restart it to apply changes.

<a id="validationaspa-default-procedure"></a>
**`validation.aspa-default-procedure`** — The procedure for peers that no
`aspa-peers` entry maps:

- `upstream` (default) — Verify every unmapped peer as a customer, lateral
  peer or route server. A provider's ordinary transit routes can fail this
  procedure, so map your providers in `aspa-peers`.
- `downstream` — Verify every unmapped peer as a provider. Use this when
  most of your BMP peers are transit providers and you map the rest.
- `auto` — Meant to read each neighbor's role from the BGP Role capability
  (RFC 9234). RAVEN does not parse BGP Role yet, so `auto` selects
  `upstream` today and RAVEN logs a WARN at startup saying so.

Routes verified with the default report `aspa_procedure_source: default`.
RAVEN never runs the neighbor-AS check on them, because it does not know
what the neighbor is.

**`validation.aspa-as-set-behavior`** — How to handle AS_PATHs containing AS_SET segments:

- `unverifiable` (default) — Mark the route as ASPA Unverifiable. Safe and correct.
- `best-effort` — Validate AS_SEQUENCE segments, skip AS_SET segments.

### Outputs Section

**`outputs.prometheus`** — Exposes a Prometheus `/metrics` endpoint. Point your
Prometheus scraper at this address. See [Observability & Metrics](observability.md)
for the full metrics reference.

**`outputs.otel`** — Optional OTLP metrics export alongside Prometheus. See
[OpenTelemetry Configuration](#opentelemetry-configuration) below.

**`outputs.kafka`** — Optional event sink that publishes events to a Kafka
topic (`brokers`, `topic`).

**`outputs.file`** — Optional event sink that appends events to a file
(`path`, `rotation`).

### API Section

<a id="apilisten"></a>
**`api.listen`** — The address the HTTP API binds to. The `raven` CLI
(`status`, `peers`, `routes`, `watch` and the rest) reads everything through
this API. Default: `127.0.0.1:11020`, so only processes on the monitoring
host can reach it.

!!! warning "Breaking change for remote CLI use"
    Earlier releases bound the API to port 11020 on every interface, with no
    setting to change it. The API now binds to loopback unless you set
    `api.listen`. If you run `raven --address <host>:11020` from another
    machine, set `api.listen` on the daemon to an address that machine can
    reach, and protect it: the API has no authentication. See
    [Keep the API on loopback](../deployment/hardening.md#keep-the-api-on-loopback).

```yaml
api:
  listen: "192.0.2.10:11020"        # reachable from the management network
```

The CLI's `--address` flag (default `localhost:11020`) is a **client-side**
setting: it tells the CLI where to reach a running RAVEN and does not change
the daemon's bind address. To query a remote instance, see
[Pointing the CLI at a Remote RAVEN Instance](#pointing-the-cli-at-a-remote-raven-instance)
below.

At startup RAVEN logs one `listeners bound` line with the address each
listener bound (`bmp`, `api`, `metrics` and, when enabled, `pprof`), so you
can confirm what is exposed. If the API cannot bind, RAVEN logs the error and
keeps running without it. If BMP cannot bind, RAVEN exits with a non-zero
status.

## Multiple RTR Caches

Running two RTR caches provides redundancy:

```yaml
rtr:
  caches:
    - address: "routinator1.example.com:3323"
      preference: 1
    - address: "routinator2.example.com:3323"
      preference: 2
```

RAVEN connects to both but treats preference 1 as authoritative. If it goes
down, RAVEN automatically uses preference 2 and logs a warning.

## Transport Security

RAVEN supports TLS on both its outbound RTR connection
(to your RPKI validator) and its inbound BMP listener
(from your routers).

### RTR over TLS

To encrypt the RTR session between RAVEN and your RPKI
validator, set `transport: tls` on the cache entry and
optionally provide a CA certificate to verify the
validator's identity:

```yaml
rtr:
  caches:
    - address: "rpki1.example.com:3324"
      preference: 1
      transport: tls
      tls:
        ca: "/etc/raven/rpki-ca.crt"   # verify validator cert
        # cert: "/etc/raven/client.crt" # optional: mutual TLS
        # key:  "/etc/raven/client.key"
        # tls-min-version: "1.2"        # 1.2 (default) | 1.3
```

If `ca` is omitted, RAVEN uses the system root CA pool.
Mutual TLS (client certificate) is supported by adding
`cert` and `key`. `tls-min-version` pins the minimum
negotiated TLS version — `"1.2"` (default) or `"1.3"` —
and is available on both the RTR `tls:` block above and
the BMP `tls:` block below.

**Routinator TLS setup:**

Routinator supports RTR-over-TLS natively. Start it
with the `--rtr-tls` flag (note: separate from
`--rtr-listen`):

```bash
routinator server \
  --rtr-tls 127.0.0.1:3324 \
  --rtr-tls-cert /path/to/server.crt \
  --rtr-tls-key  /path/to/server.key
```

The IANA-assigned port for RTR-over-TLS is 324; use
3324 to avoid requiring root privileges.

**Starting below RTR v2:**

If your validator does not support RTR v2, start at v1. RAVEN then never
asks it for version 2: no Error Report code 4 at each start and no hourly
version 2 re-probe. It still falls back to v0 if the validator turns v1
down:

```yaml
rtr:
  rtr-version: "1"
  caches:
    - address: "rpki1.example.com:3324"
      transport: tls
      tls:
        ca: "/etc/raven/rpki-ca.crt"
```

### BMP Listener TLS

To require TLS on incoming BMP connections from your
routers, add a `tls:` block under `bmp:`. A server
certificate and key are required; a CA is optional and
enables mutual TLS (verifying router client certs):

```yaml
bmp:
  listen: ":11019"
  tls:
    cert: "/etc/raven/bmp.crt"   # required
    key:  "/etc/raven/bmp.key"   # required
    ca:   "/etc/raven/ca.crt"    # optional: mutual TLS
    # tls-min-version: "1.2"     # 1.2 (default) | 1.3
```

Without the `tls:` block, the BMP listener accepts
plain TCP connections (default, compatible with all
BMP-capable routers including FRR and SR Linux).

> **Note:** Most routers do not currently support
> BMP-over-TLS. This option is intended for deployments
> where RAVEN is reachable across untrusted network
> segments. For lab and internal deployments, plain TCP
> is standard.

### Generating Test Certificates

For lab use, generate a self-signed CA and server cert
with v3 extensions (required by modern TLS stacks):

```bash
# CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout ca.key -out ca.crt -days 365 -nodes \
  -subj "/CN=raven-ca" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server cert (for Routinator or BMP listener)
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout server.key -out server.csr -nodes \
  -subj "/CN=localhost"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n\
basicConstraints=CA:false\n")
```

## Environment Variable Overrides

You can override a config key with an environment variable. This is useful
in containers and systemd units, where you want one `raven.yaml` and a
per-host setting or two. To build the variable name, take the key's full
path, prefix it with `RAVEN_`, upper-case it, and replace every dot and
dash with an underscore:

| Config key | Environment variable |
|---|---|
| `bmp.listen` | `RAVEN_BMP_LISTEN` |
| `api.listen` | `RAVEN_API_LISTEN` |
| `rtr.expire-interval` | `RAVEN_RTR_EXPIRE_INTERVAL` |
| `validation.aspa-default-procedure` | `RAVEN_VALIDATION_ASPA_DEFAULT_PROCEDURE` |
| `logging.format` | `RAVEN_LOGGING_FORMAT` |

```bash
RAVEN_API_LISTEN=192.0.2.10:11020 RAVEN_RTR_EXPIRE_INTERVAL=3600 raven serve --config /etc/raven/raven.yaml
```

An environment variable wins over the same key in `raven.yaml`. Keys inside
lists and maps have no fixed name, so you cannot set them from the
environment: the entries of `rtr.caches`, `validation.aspa-peers` and
`events.rules`, and maps such as webhook `headers` and
`outputs.otel.resource_attributes`. Set those in `raven.yaml`.

Earlier releases ignored these variables.

## Pointing the CLI at a Remote RAVEN Instance

By default the CLI connects to `localhost:11020`. To query a remote instance,
set `api.listen` on that instance to an address you can reach (see
[API Section](#api-section)), then pass `--address` on each command:

```bash
raven routes --address 192.0.2.10:11020 --posture origin-invalid
```

`--address` is a per-invocation flag — it is not read from `raven.yaml` or from
an environment variable. To avoid repeating it, wrap it in a shell alias:

```bash
alias raven-prod='raven --address 192.0.2.10:11020'
```

---

## Events Configuration

The `events` section configures the Event Engine — rules that trigger actions
when route postures change.

```yaml
events:
  rules:
    - name: "alert-origin-invalid"
      trigger:
        type: posture_change
        postures: ["origin-invalid"]
      cooldown: 60s
      actions:
        - type: log
          level: warn
        - type: webhook
          url: "https://hooks.example.com/raven"
          secret: "your-hmac-secret"
          max_attempts: 3
          timeout: 5s
        - type: flowspec
          gobgp_address: "localhost:50051"
          dry_run: true
          ttl: 5m
          rule_action: drop
          max_rules: 100
          reaper_interval: 30s

    - name: "alert-route-leak"
      trigger:
        type: posture_change
        postures: ["path-suspect"]
      cooldown: 60s
      actions:
        - type: log
          level: warn
        - type: webhook
          url: "https://hooks.example.com/raven"

    - name: "alert-any-route-via-as64496"
      trigger:
        type: asn
        asns: [64496]
        asn_match: path       # "origin" (default) or "path"
      cooldown: 60s
      actions:
        - type: log
          level: info

    - name: "alert-hijack-of-my-prefixes"
      trigger:
        type: protected_asn
        asns: [64511]
      cooldown: 60s
      actions:
        - type: log
          level: warn
        - type: webhook
          url: "https://hooks.example.com/raven"
```

**Trigger types:**

| Type | Description |
|---|---|
| `posture` | Fires whenever a route currently has one of the listed postures |
| `posture_change` | Fires when a route's posture *changes* to one of the listed values |
| `prefix` | Fires on routes matching a specific prefix |
| `asn` | Fires when a route involves one of the listed ASNs. `asn_match: origin` (default) matches the origin only; `asn_match: path` matches any ASN in the full path |
| `protected_asn` | Fires when an origin-invalid route hijacks a prefix authorised for one of the listed ASNs |
| `cache_unhealthy` | Fires when an RTR cache becomes unreachable |
| `rib` | Fires on routes in one of the RIBs in `ribs`: `adj-rib-in-pre` (or `pre-policy`), `adj-rib-in-post` (or `post-policy`), `loc-rib`, `adj-rib-out-pre`, `adj-rib-out-post`. Use it in a `compound` trigger to keep a rule to some RIBs. An empty `ribs` or an unknown name is a configuration error |
| `compound` | Combines sub-`triggers` with an `operator` of `and` or `or` |

**Action types:**

| Type | Description |
|---|---|
| `log` | Log the event at the specified level |
| `webhook` | HTTP POST with JSON payload, HMAC-SHA256 signed |
| `flowspec` | Generate a Flowspec drop rule, inject via GoBGP |
| `global-correlate` | Query external global BGP visibility and annotate the event. See [External Correlation](#external-correlation-ripestat) |

**Cooldown** — Minimum time between repeated firings of the same rule for
the same route: router, peer distinguisher, peer, prefix, path ID and RIB.
Prevents alert storms during flapping. Without `cooldown`, a rule has
none. A router that sends several RIBs fires a rule once per RIB; see
[Active Response](active-response.md#rule-structure).

**Webhook payload** — The JSON body sent to your webhook URL:

```json
{
  "id": "b65b80a6-...",
  "timestamp": "2026-10-18T14:23:01Z",
  "type": "posture_change",
  "rule_name": "alert-origin-invalid",
  "router_id": "192.0.2.1",
  "prefix": "203.0.113.0/24",
  "peer_addr": "198.51.100.1",
  "peer_distinguisher": "",
  "rib": "adj-rib-in-pre",
  "peer_asn": 64500,
  "origin_asn": 64496,
  "protected_asns": [64511],
  "old_posture": "origin-only",
  "new_posture": "origin-invalid",
  "rov_state": "Invalid",
  "aspa_state": "Unknown",
  "cache_name": ""
}
```

`rule_name` identifies which rule fired. `protected_asns` lists the ASNs named as
authorized originators in matched VRPs — present only when there are covering VRPs
(relevant for `protected_asn` trigger alerts). `rib` and
`peer_distinguisher` (`""` for a global-instance peer) are always present.

**Flowspec options:**

| Option | Default | Description |
|---|---|---|
| `gobgp_address` | `localhost:50051` | GoBGP gRPC management endpoint |
| `dry_run` | `true` | Log rules without injecting into GoBGP |
| `ttl` | `1h` | Per-rule lifetime before auto-expiry |
| `rule_action` | `drop` | Flowspec action: `drop` or `rate-limit` |
| `max_rules` | `100` | Maximum concurrently active rules |
| `reaper_interval` | `30s` | How often to check for and expire TTL'd rules |
| `approval_webhook` | — | URL to POST proposed rules to before injecting |

!!! tip
    Always start with `dry_run: true`. Use `raven flowspec list` to review
    generated rules, then toggle specific rules live with
    `raven flowspec toggle "<key>"` when you are confident they are correct.

---

## External Correlation (RIPEstat)

The `external` section configures correlation against third-party routing
data. RAVEN makes **no outbound calls** to these providers unless you opt in
here — every provider defaults to disabled.

```yaml
external:
  ripestat:
    enabled: false                 # must be true for the global-correlate action
    base-url: "https://stat.ripe.net"
    timeout: 5s
    cache-ttl: 60s
    rate-limit-per-min: 10
```

**Options:**

| Option | Default | Description |
|---|---|---|
| `enabled` | `false` | Allow the Event Engine's `global-correlate` action to query RIPEstat |
| `base-url` | `https://stat.ripe.net` | RIPEstat origin, without the data-call path. Point this at a stub or mirror for testing |
| `timeout` | `5s` | Bounds a single looking-glass query |
| `cache-ttl` | `60s` | How long a per-prefix result stays usable, so a flapping route does not re-query on every event |
| `rate-limit-per-min` | `10` | Per-instance lookup budget per minute, and the burst capacity. A good-citizen safeguard against hammering RIPEstat |

### Why This Exists

RAVEN's ROV and ASPA validation is local-vantage-point only: it knows what
your own BMP-attached routers received. That cannot distinguish a real hijack
the rest of the internet also sees from a purely local leak or
misconfiguration. Correlating against RIS route collectors closes that gap.

### The `global-correlate` Action

`enabled: true` makes a new Event Engine action type available. It queries
the looking-glass for the event's prefix and compares the globally-observed
origin ASNs against RAVEN's local BMP-observed origin.

```yaml
external:
  ripestat:
    enabled: true

events:
  rules:
    - name: "correlate-suspicious-routes"
      trigger:
        type: posture_change
        postures: ["origin-invalid", "path-suspect"]
      cooldown: 60s
      actions:
        - type: global-correlate
          cache_ttl: 60s        # optional; defaults to external.ripestat.cache-ttl
        - type: log
          level: warn
        - type: webhook
          url: "https://hooks.example.com/raven"
```

**Action options:**

| Option | Default | Description |
|---|---|---|
| `cache_ttl` | `external.ripestat.cache-ttl` | This rule's freshness requirement. A cached result younger than this is reused instead of re-querying |

`global-correlate` runs to completion **before** the rule's other actions,
so they all observe the annotation. Ordering within the `actions` list does
not matter.

When a rule includes it, the webhook payload gains a `global_visibility`
object and the `log` action gains `global_consensus`, `global_source`,
`global_collectors`, `global_majority_origin` and `global_error` keys. Rules
without the action are completely unaffected — no new webhook field, no new
log keys.

```json
{
  "id": "b65b80a6-...",
  "type": "posture_change",
  "prefix": "203.0.113.0/24",
  "origin_asn": 64511,
  "new_posture": "origin-invalid",
  "global_visibility": {
    "queried": true,
    "source": "ripestat",
    "queried_at": "2026-09-08T14:23:01Z",
    "local_origin": 64511,
    "global_origins": [
      { "asn": 65000, "collector_count": 18 },
      { "asn": 64511, "collector_count": 4 }
    ],
    "consensus": "divergent",
    "collector_count": 22,
    "latency_ns": 512000000
  }
}
```

**Consensus values:**

| Value | Meaning |
|---|---|
| `match` | The local origin is the single most-observed origin globally |
| `divergent` | The world's majority origin is not the local origin, or the local origin is only tied for most-observed (a MOAS conflict) |
| `local_only` | No collector sees this prefix at all — a local leak or misconfiguration, not a propagated hijack |
| `inconclusive` | Query failed, timed out, returned malformed data, was suppressed by the rate limiter, or there was no local origin to compare against. `error` carries the cause |

### Operational Guarantees

- **Never on the hot path.** Correlation runs in the Event Engine's own
  goroutines, never in BMP ingest or validation. There are no per-route
  external HTTP calls: it fires only on a matching rule, behind the cache
  and rate limiter.
- **Bounded.** At most 4 correlations are in flight at once, each with its
  own 10s timeout, on top of the per-minute budget.
- **Fail-open.** An unreachable, slow or malformed RIPEstat produces an
  `inconclusive` annotation. It never crashes RAVEN, fails a rule, or blocks
  any other action.
- **A separate annotation.** The result does not feed into the route's
  [security posture](security-postures.md); the ROV × ASPA matrix is
  unchanged.
- **Fails loudly on misconfiguration.** A rule using `global-correlate`
  while `external.ripestat.enabled` is `false` is rejected at startup,
  rather than silently emitting `inconclusive` annotations forever.

For the equivalent one-shot check from the command line, see
[CLI Reference → raven check global](cli-reference.md#raven-check-global).
That command does not require `enabled: true`.

!!! note
    Counts are in units of **collector peers** — one (route collector, peer
    address) pair — not collectors. A single RIS collector peering with 30
    networks contributes up to 30 observations.

---

## Persistence (Warm-Start Snapshots)

The `persistence` section configures warm-start snapshots — saving the route
table and RPKI cache to disk so RAVEN can restore state quickly on restart.

```yaml
persistence:
  enabled: true
  snapshot_dir: "/var/lib/raven/snapshots"   # directory, not a file
  stale_eviction_timeout: 5m                 # evict unconfirmed restored routes after this
```

**Options:**

| Option | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable snapshot save/restore |
| `snapshot_dir` | `~/.raven/snapshots` | Directory for snapshot files (supports `~` expansion) |
| `stale_eviction_timeout` | `5m` | Routes restored from a snapshot but never confirmed by a live BMP message are evicted this long after startup |

Without persistence, RAVEN rebuilds its route table from BMP table dumps on
restart (typically 30–90 seconds). With it, the route table is available
immediately on startup while BMP reconnects in the background.

---

## OpenTelemetry Configuration

The `outputs.otel` section configures OTLP metrics export alongside Prometheus.

```yaml
outputs:
  otel:
    enabled: true
    endpoint: "otel-collector:4317"
    protocol: grpc               # grpc | http
    interval: 30s
    insecure: true              # true = no TLS on the OTLP connection
    headers:                    # optional per-request headers (e.g. auth)
      x-api-key: "secret"
    resource_attributes:        # attached to every exported metric
      service.name: "raven"
      service.version: "v0.1.0"
```

**Options:**

| Option | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable OpenTelemetry export |
| `endpoint` | `localhost:4317` | OTLP collector endpoint |
| `protocol` | `grpc` | Export protocol: `grpc` or `http` |
| `interval` | `30s` | Metrics export interval |
| `insecure` | `true` | Disable TLS on the OTLP connection |
| `headers` | — | Optional map of headers sent with each OTLP request |
| `resource_attributes` | `service.name=raven`, `service.version=v0.1.0` | Resource attributes attached to exported metrics. Set the service name here — there is no separate `service_name` option |

RAVEN exports the same metrics via OTLP as via Prometheus. Both outputs
can be active simultaneously. RAVEN continues normally if the OTLP
collector is unreachable — export failures are logged but not fatal.
