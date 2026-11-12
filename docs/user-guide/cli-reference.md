# CLI Reference

RAVEN is CLI-first. Every command connects to a running RAVEN daemon via the
API (default: `localhost:11020`). Use `--address` to target a remote
instance; that instance must set
[`api.listen`](configuration.md#api-section) to an address you can reach,
because the API binds to loopback by default.

## Global Flags

These persistent flags are accepted by every command:

| Flag | Default | Description |
|---|---|---|
| `--address` | `localhost:11020` | RAVEN daemon address for CLI queries |
| `--config` | `./raven.yaml` | Config file path (search order: `./raven.yaml`, then `/etc/raven/raven.yaml`). Only `serve` reads the daemon config |
| `--log-level` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `--log-format` | `json` | Log format: `json` or `text` |

!!! note
    `--format` is **not** a global flag. It is a per-command flag: `table` or
    `json` on most commands, `wide` as well on `raven routes`, and `markdown`
    on `raven audit`. `raven status`, `raven peers` and `raven validate` have
    no `--format`.
    Each command's flag table below lists whether it accepts `--format`.

---

## raven serve

Start the RAVEN daemon — BMP listener, RTR client, validation engine, and all
configured outputs.

```bash
raven serve
raven serve --config /etc/raven/raven.yaml
raven serve --config raven.yaml
```

RAVEN runs in the foreground. Use systemd, screen, or tmux for production.

**What happens on startup:**

1. Loads config file
2. Starts Prometheus metrics endpoint
3. Starts API server
4. Connects to RTR caches — downloads VRPs and ASPA data
5. Starts BMP listener — waits for router connections
6. As routers connect, receives table dumps and begins validation

---

## raven status

Show the route table summary, RPKI state and every BMP peer.

```bash
raven status
raven status --router edge1
```

**Flags:**

| Flag | Description |
|---|---|
| `--router` | List only this monitored router's peers: its BMP source address or its BMP sysName. The route table and RPKI totals stay daemon-wide |

`raven status` has no `--format` flag. For JSON, read the API directly on
the monitoring host:

```bash
curl -s http://127.0.0.1:11020/api/v1/status
```

**Example output:**

```text
RAVEN dev  uptime 2h14m5s

Route Table: 4 routes in the default view (adj-rib-in-pre + loc-rib)
  origin-only          3
  origin-invalid       1
By RIB:
  adj-rib-in-pre       1
  loc-rib              3

RPKI: 2 VRPs (serial 4821)

BMP Peers: 2
  ROUTER  PEER          TYPE     ASN    STATE  ROUTES
  rr1     198.51.100.7  global   64500  up     1
  rr1     loc-rib       loc-rib  64499  up     3
```

Here `rr1` (AS64499, at 192.0.2.3) exports both its pre-policy Adj-RIB-In and its
Loc-RIB; see [Loc-RIB Monitoring](loc-rib.md).

**Route Table** and its posture breakdown count the
[default view](../getting-started/concepts.md#which-rib-to-monitor):
Adj-RIB-In pre-policy plus Loc-RIB, the RIBs the header names, which are
the routes `raven routes` lists without `--rib`. A router that sends both
counts most of its routes twice, once per RIB; a router that sends only its
Loc-RIB no longer shows 0. v0.4.0 counted Adj-RIB-In pre-policy only. The
postures are listed in a fixed order: `secured`, `path-only`,
`origin-only`, `unverified`, `path-suspect`, `origin-invalid`, each only
when it has routes. **By RIB** lists every RIB that has routes, in the
order `adj-rib-in-pre`, `adj-rib-in-post`, `loc-rib`, `adj-rib-out-pre`,
`adj-rib-out-post`.

**BMP Peers** columns:

| Column | Meaning |
|---|---|
| `ROUTER` | The monitored router: its BMP sysName, or its BMP source address when it sent none |
| `PEER` | The BGP peer's address. A peer in a VRF shows the VRF's route distinguisher, as in `2001:db8::2 rd 65000:100`. A Loc-RIB instance shows `loc-rib`, with the RD of a VRF instance, as in `loc-rib rd 64499:100` |
| `TYPE` | The BMP peer type: `global`, `rd` (a VRF peer), `local`, or `loc-rib` (the router's Loc-RIB instance, RFC 9069) |
| `ASN` | The peer's ASN; for a Loc-RIB instance, the router's own AS |
| `STATE` | `up` or `down` |
| `ROUTES` | A BGP peer's Adj-RIB-In pre-policy routes, or a Loc-RIB instance's Loc-RIB routes, now in the table |
| `OUT` | The peer's Adj-RIB-Out pre-policy routes: what your router sends that peer (RFC 8671). Shown only when some peer has Adj-RIB-Out routes |

The API's `/api/v1/status` and `/api/v1/peers` give each peer a
`peer_type` and, for a Loc-RIB instance that sent a Peer Up, a
`table_name`: its VRF/Table Name, `global` for the default instance.
`/api/v1/status` also names the default view's RIBs in `route_table`:

```json
"route_table": {
  "total_routes": 4,
  "default_view": ["adj-rib-in-pre", "loc-rib"],
  "by_posture": {"origin-invalid": 1, "origin-only": 3},
  "by_rib": {"adj-rib-in-pre": 1, "loc-rib": 3}
}
```

The same peer address on two routers, or in two VRFs of one router, is two
rows, because RAVEN keys peers by router, peer distinguisher and address.
`ROUTES` and `OUT` stay in separate columns so that received and sent routes
are never added together.

---

## raven peers

List every BMP peer with session metadata.

```bash
raven peers
raven peers --router edge1
```

**Flags:**

| Flag | Description |
|---|---|
| `--router` | List only this monitored router's peers: its BMP source address or its BMP sysName |

`raven peers` has no `--format` flag; for JSON, read
`http://127.0.0.1:11020/api/v1/peers` on the monitoring host.

**Example output:**

```text
ROUTER  PEER          TYPE     ASN    ROUTER ID     STATE  ROUTES  UP SINCE
rr1     198.51.100.7  global   64500  198.51.100.7  up     1       2026-10-18T09:12:44Z
rr1     loc-rib       loc-rib  64499  192.0.2.3     up     3       2026-10-18T09:12:44Z
```

The `ROUTER`, `PEER`, `TYPE`, `ASN`, `ROUTES` and `OUT` columns mean the
same as in [`raven status`](#raven-status). `ROUTER ID` is the peer's BGP
identifier (for a Loc-RIB instance, the router's own) and `UP SINCE` the
time its session came up (RFC 3339, UTC); for a Loc-RIB instance that sent
no Peer Up, the time RAVEN registered it from its first routes.

The API's `/api/v1/peers` output for a Loc-RIB instance:

```json
{
  "router": "192.0.2.3",
  "router_name": "rr1",
  "peer_type": "loc-rib",
  "table_name": "global",
  "addr": "0.0.0.0",
  "asn": 64499,
  "router_id": "192.0.2.3",
  "state": "up",
  "route_count": 3,
  "routes_by_rib": {
    "loc-rib": 3
  },
  "up_since": "2026-10-18T09:12:44Z",
  "last_msg": "2026-10-18T09:12:44Z"
}
```

`table_name` is omitted for a VRF instance that sent no Peer Up (FRR 10.2
sends none for its Loc-RIB); the default instance is `global` either way.
`peer_distinguisher` is omitted for the default instance.

### The MALFORMED column

When a peer has sent a malformed UPDATE that RFC 7606 answers with a
session reset, `raven peers` adds a `MALFORMED` column. It shows the reason
for that peer and `-` for every other peer:

```text
ROUTER  PEER          TYPE    ASN    ROUTER ID     STATE  ROUTES  UP SINCE              MALFORMED
edge1   198.51.100.1  global  64500  198.51.100.1  up     2       2026-10-18T09:12:44Z  mp_reach_next_hop
edge1   198.51.100.2  global  64496  198.51.100.2  up     1       2026-10-18T09:12:44Z  -
```

A marked peer's routes in RAVEN may be incomplete: RAVEN withdrew what it
could parse from the bad UPDATE and expects the router to reset the BGP
session. The mark clears when the router reports the peer up again (BMP
Peer Up). The reason is a `raven_bmp_malformed_updates_total` reason, and
the API's `/api/v1/peers` output carries it as `malformed_input`,
`malformed_reason` and `malformed_since`. See
[Malformed BGP Input](../troubleshooting.md#malformed-bgp-input).

---

## raven routes

Query the route table. Without filters, RAVEN returns every route in the
[default view](../getting-started/concepts.md#which-rib-to-monitor):
Adj-RIB-In pre-policy and Loc-RIB.

```bash
raven routes
raven routes --prefix 203.0.113.0/24
raven routes --prefix 203.0.113.128/25 --match covering
raven routes --prefix 203.0.112.0/22 --match longer
raven routes --origin-asn 64502
raven routes --peer 198.51.100.1
raven routes --router edge1
raven routes --posture path-suspect
raven routes --prefix 203.0.113.0/24 --peer 198.51.100.1
raven routes --posture path-suspect --format wide
raven routes --rib adj-rib-out-pre --posture origin-invalid
raven routes --rib loc-rib
raven routes --rib pre-policy,post-policy --prefix 203.0.113.0/24
raven routes --format json
```

**Flags:**

| Flag | Description |
|---|---|
| `--prefix` | Filter by prefix: exactly this prefix, unless `--match` says otherwise |
| `--match` | How `--prefix` matches: `exact` (default), `covering` (the prefix and every less specific prefix in the table that covers it) or `longer` (the prefix and every more specific prefix within it). Needs `--prefix` |
| `--origin-asn` | Filter by origin ASN |
| `--peer` | Filter by BMP peer address. An IPv4 peer matches in plain or IPv4-mapped form |
| `--router` | Filter by monitored router: its BMP source address or its BMP sysName |
| `--posture` | Filter by security posture |
| `--rib` | The RIBs to list, comma-separated: `adj-rib-in-pre` (or `pre-policy`), `adj-rib-in-post` (or `post-policy`), `loc-rib`, `adj-rib-out-pre`, `adj-rib-out-post`. Default: the default view, `adj-rib-in-pre` and `loc-rib` |
| `--format` | Output format: `table` (default), `wide` or `json` |

Every filter you give applies, so `--prefix 203.0.113.0/24 --peer
198.51.100.1` returns that prefix from that one peer. Earlier releases
honored only the first filter present and silently ignored the rest.
`--router` with a sysName matches every router that reported that name.

Without `--rib`, `raven routes` lists the default view: Adj-RIB-In
pre-policy, what your peers actually sent before your import policy
changed or filtered it, and Loc-RIB, the best paths your routers selected.
A router that sends only its Loc-RIB still shows its routes, and a router
that sends both shows a prefix once per RIB; the `RIB` column tells them
apart. `--rib` names the RIBs to list instead, one or several separated by
commas, and every other filter applies within them. Use `--rib loc-rib` for
the routes your routers use, `--rib adj-rib-in-post` to see what survived
your import policy, and `--rib adj-rib-out-pre` to check what your router
advertises, for example `origin-invalid` routes your network is sending to
its peers. A RIB shows routes only if your routers export it over BMP.

v0.4.0 listed Adj-RIB-In pre-policy only without `--rib`, and took one RIB
per query.

The API takes the same filter as the `rib` query parameter on
`/api/v1/routes` and `/api/v1/watch`, with the same values, comma-separated
or repeated (`rib=loc-rib,adj-rib-in-post` or
`rib=loc-rib&rib=adj-rib-in-post`). Without it, both return the default
view. An unknown value returns HTTP 400, for example for `rib=adj-rib-in`:

```text
invalid rib: unknown RIB "adj-rib-in": want adj-rib-in-pre (or pre-policy), adj-rib-in-post (or post-policy), loc-rib, adj-rib-out-pre or adj-rib-out-post
```

**Posture values for `--posture`:**

`secured` `origin-only` `path-suspect` `path-only` `unverified` `origin-invalid`

### --match

`--prefix` alone is an exact match: `--prefix 203.0.113.0/24` returns
routes for `203.0.113.0/24` and nothing else, not the `/16` that covers it
or the `/25`s inside it. That is the default, as it always was. `--match`
widens it:

- `--match covering` returns the prefix and every less specific prefix in
  the table that covers it, least specific first. Use it to see what
  traffic to an address or a more-specific would follow if that route were
  withdrawn or rejected: `--prefix 203.0.113.7/32 --match covering`. The
  prefix itself need not be in the table.
- `--match longer` returns the prefix and every more specific prefix
  within it, in address order: `--prefix 203.0.112.0/22 --match longer`
  lists the `/22` and every `/23`, `/24` and longer inside it, for example
  more-specifics hijacking part of your space.

Both use the route table's prefix index rather than scanning the table,
and every other filter applies to the routes they return. Host bits in
`--prefix` are ignored with `covering` and `longer`. The API takes the same
values as the `match` query parameter on `/api/v1/routes` and
`/api/v1/watch`; an unknown value, or `covering` or `longer` without
`prefix`, returns HTTP 400.

**Example output:**

```text
PREFIX                    ROUTER     PEER                             RIB             ORIGIN   ROV       ASPA     POSTURE
203.0.113.0/24            edge1      198.51.100.1                     adj-rib-in-pre  AS64502  Valid     Invalid  path-suspect
198.51.100.0/24           edge1      192.0.2.250                      adj-rib-in-pre  AS64503  NotFound  Valid    path-only
2001:db8:2000::/36        edge1      198.51.100.1                     adj-rib-in-pre  AS64503  NotFound  Invalid  path-suspect
203.0.113.0/24            edge1      198.51.100.2                     adj-rib-in-pre  AS64502  Valid     Valid    secured
2001:db8:3000::/36        192.0.2.2  2001:db8::2 rd 65000:100 path 2  adj-rib-in-pre  AS64504  NotFound  Unknown  unverified
```

`ROUTER` is the router's sysName, or its address when it sent none. `PEER`
adds the VRF's route distinguisher for a peer in a VRF, and the path ID
when the peer uses ADD-PATH (RFC 7911), as in
`2001:db8::2 rd 65000:100 path 2`, because the peer can send several paths
for one prefix and RAVEN keeps each one. `RIB` is the route's RIB.

A Loc-RIB route has no peer, so `PEER` shows `-` (followed by `rd` and the
RD for a VRF's Loc-RIB). Here `rr1` (AS64499, at 192.0.2.3) sends its
pre-policy Adj-RIB-In and its Loc-RIB, which holds two routes of its own:

```text
PREFIX                    ROUTER  PEER          RIB             ORIGIN   ROV      ASPA     POSTURE
203.0.113.0/24            rr1     198.51.100.7  adj-rib-in-pre  AS64502  Valid    Unknown  origin-only
2001:db8:ffff::1/128      rr1     -             loc-rib         AS64499  Invalid  Unknown  origin-invalid
2001:db8:100::/48         rr1     -             loc-rib         AS64499  Valid    Unknown  origin-only
203.0.113.0/24            rr1     -             loc-rib         AS64502  Valid    Unknown  origin-only
```

`2001:db8:100::/48` is a prefix `rr1` originates, and `2001:db8:ffff::1/128`
a loopback it learned over iBGP. Both have an empty AS_PATH, so their
origin is `rr1`'s own AS (see
[The origin AS](../architecture/validation-engine.md#the-origin-as)). The
loopback is `Invalid` because it is more specific than the maxLength (/48)
of the ROA for `2001:db8::/32`; see
[Internal routes show as Invalid](../troubleshooting.md#internal-routes-show-as-invalid).

### --format wide

`--format wide` adds the VRP that decided each route's ROV result, and
three columns that explain its ASPA result:

```text
PREFIX                    ROUTER     PEER                             RIB             ORIGIN   ROV       ASPA     POSTURE       VRP                        ASPA PROCEDURE  PROCEDURE SOURCE  FAILING HOP
203.0.113.0/24            edge1      198.51.100.1                     adj-rib-in-pre  AS64502  Valid     Invalid  path-suspect  203.0.113.0/24-24 AS64502  upstream        config-asn        64501->64500
198.51.100.0/24           edge1      192.0.2.250                      adj-rib-in-pre  AS64503  NotFound  Valid    path-only     -                          upstream        config-address    -
2001:db8:2000::/36        edge1      198.51.100.1                     adj-rib-in-pre  AS64503  NotFound  Invalid  path-suspect  -                          upstream        config-asn        -
203.0.113.0/24            edge1      198.51.100.2                     adj-rib-in-pre  AS64502  Valid     Valid    secured       203.0.113.0/24-24 AS64502  downstream      config-address    -
2001:db8:3000::/36        192.0.2.2  2001:db8::2 rd 65000:100 path 2  adj-rib-in-pre  AS64504  NotFound  Unknown  unverified    -                          upstream        default           -
```

| Column | Meaning |
|---|---|
| `VRP` | The VRP that decided the route's ROV result, as `prefix-maxLength ASn`, or `-` when none covers it (`NotFound`). For `Valid`, the VRP that matched; for an `Invalid` route the one its `rov_reason` names (see [ROV reasons](#rov-reasons)) |
| `ASPA PROCEDURE` | `upstream` or `downstream`: the verification procedure RAVEN used for this route |
| `PROCEDURE SOURCE` | Where the procedure came from: `config-address` (an `aspa-peers` entry for the peer address), `config-asn` (an `aspa-peers` entry for the peer ASN; for a Loc-RIB route, for the neighbor AS in its path) or `default` (`aspa-default-procedure`) |
| `FAILING HOP` | For an ASPA `Invalid`, the hop that failed, as `customer->provider`: the customer AS's ASPA record does not list that provider. `-` when no hop failed |

In the example, the first route is a leak: AS64501's ASPA record does not
list AS64500, so the hop `64501->64500` fails. The third route is `Invalid`
with no failing hop because it failed the neighbor-AS check; `--format json`
shows the reason in `aspa_reason`. The route from the transit provider
(`198.51.100.2`) is verified `downstream` because an `aspa-peers` entry maps
that address to `neighbor-role: provider`. See
[ASPA Path Verification](../getting-started/concepts.md#aspa-path-verification)
and [`validation.aspa-peers`](configuration.md#validationaspa-peers).

### --format json

`--format json` prints the API's response unchanged: an array of route
objects. This is the leaking route from the examples above:

```json
[
  {
    "prefix": "203.0.113.0/24",
    "router": "192.0.2.1",
    "router_name": "edge1",
    "peer_type": "global",
    "peer": "198.51.100.1",
    "peer_asn": 64500,
    "rib": "adj-rib-in-pre",
    "origin_asn": 64502,
    "as_path": [
      64500,
      64501,
      64502
    ],
    "next_hop": "198.51.100.1",
    "communities": [
      "64500:120"
    ],
    "rov": "Valid",
    "rov_reason": "matches VRP {203.0.113.0/24, AS64502, /24}",
    "rov_reason_code": "valid",
    "rov_vrps": {
      "matched": [
        {
          "prefix": "203.0.113.0/24",
          "asn": 64502,
          "max_length": 24
        }
      ],
      "unmatched_as": [],
      "unmatched_length": []
    },
    "rov_deciding_vrp": {
      "prefix": "203.0.113.0/24",
      "asn": 64502,
      "max_length": 24
    },
    "aspa": "Invalid",
    "aspa_procedure": "upstream",
    "aspa_procedure_source": "config-asn",
    "aspa_failing_hop": {
      "customer_asn": 64501,
      "provider_asn": 64500
    },
    "posture": "path-suspect",
    "timestamp": "2026-10-18T14:02:31Z"
  }
]
```

A route from a VRF peer with ADD-PATH carries `peer_distinguisher` and
`path_id`; a route that failed the neighbor-AS check carries `aspa_reason`:

```json
{
  "prefix": "2001:db8:3000::/36",
  "router": "192.0.2.2",
  "peer_distinguisher": "65000:100",
  "peer_type": "rd",
  "peer": "2001:db8::2",
  "peer_asn": 64505,
  "path_id": 2,
  "rib": "adj-rib-in-pre",
  ...
}
```

A Loc-RIB route has `peer_type` `loc-rib`, the zero peer address, and the
router's own AS as `peer_asn`. This is `rr1`'s loopback from the example
above, from `raven routes --rib loc-rib --format json`:

```json
{
  "prefix": "2001:db8:ffff::1/128",
  "router": "192.0.2.3",
  "router_name": "rr1",
  "peer_type": "loc-rib",
  "peer": "0.0.0.0",
  "peer_asn": 64499,
  "rib": "loc-rib",
  "origin_asn": 64499,
  "as_path": null,
  ...
  "rov": "Invalid",
  "rov_reason": "prefix length /128 exceeds maxLength /48 of VRP 2001:db8::/32 AS64499; origin is the router's own AS: empty AS_PATH (RFC 6811 §2)",
  "rov_reason_code": "invalid_length",
  "rov_vrps": {
    "matched": [],
    "unmatched_as": [],
    "unmatched_length": [
      {
        "prefix": "2001:db8::/32",
        "asn": 64499,
        "max_length": 48
      }
    ]
  },
  ...
  "aspa": "Unknown",
  "aspa_procedure": "upstream",
  "aspa_procedure_source": "default",
  "aspa_reason": "not ASPA-verified: empty AS_PATH; the route is locally originated or iBGP-learned without an AS_PATH",
  "posture": "origin-invalid",
  ...
}
```

```json
{
  "prefix": "2001:db8:2000::/36",
  ...
  "aspa": "Invalid",
  "aspa_procedure": "upstream",
  "aspa_procedure_source": "config-asn",
  "aspa_reason": "neighbor-AS check failed: first AS in AS_PATH is AS64511, peer is AS64500",
  ...
}
```

**Route fields:**

| Field | Description |
|---|---|
| `prefix` | The route's prefix |
| `router` | The monitored router: the source address of its BMP session |
| `router_name` | The router's BMP Initiation sysName. Omitted when the router sent none |
| `peer_distinguisher` | The peer's VRF route distinguisher, from the BMP per-peer header. Omitted for peers in the global instance |
| `peer_type` | The BMP peer type: `global`, `rd`, `local`, or `loc-rib` for a Loc-RIB route (RFC 9069) |
| `peer` | The BGP peer's address; `0.0.0.0` for a Loc-RIB route |
| `peer_asn` | The BGP peer's ASN; the router's own AS for a Loc-RIB route |
| `path_id` | The ADD-PATH path identifier (RFC 7911). Omitted when ADD-PATH is not in effect for that peer and address family |
| `rib` | The RIB the route is in: `adj-rib-in-pre`, `adj-rib-in-post`, `loc-rib`, `adj-rib-out-pre` or `adj-rib-out-post`, always one of the RIBs you asked for with `--rib` (the default view's without it) |
| `origin_asn` | The origin AS (RFC 6811 §2): the last AS of the AS_PATH's final AS_SEQUENCE, or the router's own AS for an empty AS_PATH or one ending in a confederation segment (see [The origin AS](../architecture/validation-engine.md#the-origin-as)). `0` when the route has no origin (a path ending in an AS_SET, origin NONE) or RAVEN does not know the router's AS. The table shows `-` |
| `as_path` | The AS_PATH, neighbor first, origin last |
| `next_hop` | The BGP next hop |
| `communities` | The route's BGP communities (RFC 1997) as `high:low`, for example `65535:666` (BLACKHOLE, RFC 7999). Omitted when it has none |
| `large_communities` | The route's large communities (RFC 8092) as `global:local1:local2`, for example `6695:1911:172`. Omitted when it has none |
| `rov` | `Valid`, `Invalid` or `NotFound` |
| `rov_reason` | Why ROV reached its result, naming the VRP that decided it (see [ROV reasons](#rov-reasons)) |
| `rov_reason_code` | The reason as a code: `valid`, `not_found`, `invalid_length`, `invalid_origin`, `invalid_as0` or `invalid_as_set`. Omitted for a route restored from a snapshot that RAVEN has not revalidated yet |
| `rov_vrps` | The VRPs covering the route, split as Routinator's validity API splits them: `matched` (the route's origin AS, maxLength at least its prefix length), `unmatched_as` (another AS, AS0 included) and `unmatched_length` (the route's origin AS, maxLength shorter than its prefix). Each entry is `{prefix, asn, max_length}`. Each list shows at most 16 VRPs; a longer one has its full length in `matched_count`, `unmatched_as_count` or `unmatched_length_count`, which are omitted otherwise |
| `rov_deciding_vrp` | `{prefix, asn, max_length}`: the VRP `rov_reason` names, the `VRP` column of `--format wide`. Omitted for `not_found` |
| `aspa` | `Valid`, `Invalid`, `Unknown` or `Unverifiable` |
| `aspa_procedure` | `upstream` or `downstream` |
| `aspa_procedure_source` | `config-address`, `config-asn` or `default` |
| `aspa_reason` | Why ASPA reached its result when no hop explains it: the neighbor-AS check failed; or RAVEN did not verify the route because it is an Adj-RIB-Out route, its AS_PATH has confederation segments or is empty, RAVEN has no ASPA data yet (`no ASPA data (no RTR v2 session)`) or ASPA is disabled (`ASPA disabled`). Omitted otherwise |
| `aspa_failing_hop` | `{customer_asn, provider_asn}`: the hop that made ASPA `Invalid`. Omitted when no hop failed |
| `posture` | The combined [security posture](security-postures.md) |
| `timestamp` | When the monitored router received the route, from the BMP per-peer header, in RFC 3339 UTC. If the router sends a zero timestamp, RAVEN uses the time it received the BMP message instead |

### ROV reasons

RAVEN classifies each ROV result the way RFC 6811 and Routinator's validity
API do, and `rov_reason_code` and `rov_reason` say which case applied:

| `rov_reason_code` | `rov` | When | Example `rov_reason` |
|---|---|---|---|
| `valid` | `Valid` | A covering VRP has the route's origin AS and a maxLength at least its prefix length | `matches VRP {94.177.129.0/24, AS202744, /24}` |
| `not_found` | `NotFound` | No VRP covers the prefix, or RAVEN does not know the origin | `no covering VRPs found` |
| `invalid_length` | `Invalid` | A covering VRP has the route's origin AS, but the prefix is longer than its maxLength. This wins over `invalid_origin` when other VRPs name other ASes: the holder authorized this AS, just not this length | `prefix length /32 exceeds maxLength /24 of VRP 94.177.129.0/24 AS202744` |
| `invalid_origin` | `Invalid` | Covering VRPs exist, none has the route's origin AS, and not all are AS0. The reason names the most specific one | `origin AS64666 not authorized by any covering VRP; nearest VRP 203.0.113.0/24 AS64502 maxLength /24` |
| `invalid_as0` | `Invalid` | Every covering VRP is AS0 (RFC 6483 §4): the holder says the prefix should not be routed | `every covering VRP is AS0 (RFC 6483 §4); nearest VRP 192.0.2.0/24 AS0 maxLength /24` |
| `invalid_as_set` | `Invalid` | The AS_PATH ends in an AS_SET, so the origin is NONE (RFC 6811 §2), which no VRP matches | `origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2), which no covering VRP can match` |

When the origin is your router's own AS, the reason ends with why, as in
the Loc-RIB example above.

Earlier releases reported every `Invalid` route with a known origin as
`origin ASn not authorized by any covering VRP`, including the far more
common case of a more-specific announced by the right AS but beyond its
ROA's maxLength. The `rov` state and the posture were right; only the
reason was wrong.

RAVEN stores only the code with each route. `rov_vrps` and
`rov_deciding_vrp` are looked up in the VRP store when you list the route,
so right after an RTR update, before revalidation has reached the route,
they can reflect the new VRPs while `rov`, `rov_reason` and
`rov_reason_code` still show the result from before it.

`timestamp` comes from the router, not from RAVEN's clock: it is when the
monitored router received the route (RFC 7854 §4.2), not when RAVEN read
it. When RAVEN restarts or a BMP session reconnects, the router resends its
whole table, and a timestamp taken by RAVEN would make every route look
seconds old. The router's timestamp keeps the route's age, so for an
`origin-invalid` route it tells you how long the hijacked prefix has been in
your router's table, which is what you need to judge impact. The router
decides what it puts in this field, and a router that sends 0 gets RAVEN's
receive time instead; compare a few routes against the router's own
"received" time before you rely on it for route age.

---

## raven validate

Show how RAVEN validated the routes it holds for one prefix, with the reason
for each ROV result. Use it to answer "why is this prefix `origin-invalid`?"
from the daemon's live state.

```bash
raven validate --prefix 203.0.113.0/24
```

`raven validate` reads the route table of a running daemon, so it needs
`raven serve` running and the prefix received over BMP. It does not validate
a prefix the routers have not sent; for a prefix RAVEN has not seen, it
prints `no routes found for prefix 203.0.113.0/24`.

**Flags:**

| Flag | Description |
|---|---|
| `--prefix` | Prefix to look up, exact match (required) |
| `--origin-asn` | Not supported yet: `raven validate` exits with an error if you pass it |
| `--rtr` | Not supported yet: `raven validate` exits with an error if you pass it |

Both flags are reserved for one-shot validation against an RTR cache, which
does not exist yet. Earlier releases accepted them and silently ignored
them; RAVEN now refuses them so that you never read a result for an origin
you did not get. With either flag, `raven validate` prints, and exits with
status 1:

```text
Error: --origin-asn is not supported yet; validate reads the running daemon's routes for --prefix
```

```text
Error: --rtr is not supported yet; validate reads the running daemon's routes for --prefix
```

`raven validate` has no `--format` flag. For JSON, use
`raven routes --prefix 203.0.113.0/24 --format json`.

**Example output:**

```text
PREFIX                    PEER          ORIGIN   ROV      POSTURE         REASON
203.0.113.0/24            198.51.100.1  AS64502  Valid    secured         matches VRP {203.0.113.0/24, AS64502, /24}
203.0.113.0/24            198.51.100.9  AS64511  Invalid  origin-invalid  origin AS64511 not authorized by any covering VRP; nearest VRP 203.0.113.0/24 AS64502 maxLength /24
```

There is one row per route RAVEN holds for the prefix: one per peer, per
router and per ADD-PATH path. `REASON` is the ROV reason (see
[ROV reasons](#rov-reasons)), naming the VRP that decided it, or
`no covering VRPs found`, followed for a route whose origin is the
router's own AS by why it is (see
[The origin AS](../architecture/validation-engine.md#the-origin-as)).
Like `raven routes` without `--rib`, it lists the default view, Adj-RIB-In
pre-policy and Loc-RIB. It has no `RIB` column: a Loc-RIB route shows the
peer `0.0.0.0`, as the second row here, `rr1`'s Loc-RIB route for the
prefix:

```text
PREFIX                    PEER          ORIGIN   ROV    POSTURE      REASON
203.0.113.0/24            198.51.100.7  AS64502  Valid  origin-only  matches VRP {203.0.113.0/24, AS64502, /24}
203.0.113.0/24            0.0.0.0       AS64502  Valid  origin-only  matches VRP {203.0.113.0/24, AS64502, /24}
```

---

## raven watch

Stream route updates to your terminal as RAVEN validates them. Runs until you
press Ctrl+C.

```bash
raven watch
raven watch --posture path-suspect
raven watch --router edge1 --posture origin-invalid
raven watch --peer 198.51.100.1
raven watch --prefix 203.0.113.0/24 --origin-asn 64502
raven watch --rib loc-rib --posture origin-invalid
```

**Flags:**

| Flag | Description |
|---|---|
| `--prefix` | Only stream routes for this prefix |
| `--origin-asn` | Only stream routes with this origin ASN |
| `--peer` | Only stream routes from this BMP peer |
| `--router` | Only stream routes from this monitored router: its address or BMP sysName |
| `--posture` | Only stream routes with this posture |
| `--rib` | Only stream routes of these RIBs, comma-separated, with the same names as [`raven routes --rib`](#raven-routes). Default: the default view, `adj-rib-in-pre` and `loc-rib` |

Every filter you give applies, as with `raven routes`. Earlier releases sent
only `--posture` to the daemon and ignored the other filters. Without
`--rib`, the stream carries the default view; v0.4.0 streamed every RIB,
Adj-RIB-Out included, when no RIB was given.

**Example output:**

```text
watching for route events... (Ctrl+C to stop)

[path-suspect] 203.0.113.0/24 via 198.51.100.1 rib:adj-rib-in-pre origin:AS64502 AS_PATH:[64500 64501 64502] rov:Valid ASPA:Invalid hop(64501→64500) posture:path-suspect
[origin-invalid] 2001:db8:ffff::1/128 via loc-rib rib:loc-rib origin:AS64499 AS_PATH:[] rov:Invalid ASPA:Unknown posture:origin-invalid
```

`rib:` is the route's RIB. A Loc-RIB route shows `via loc-rib`, since it
has no peer.

An ASPA Invalid shows the hop that failed as `hop(C→P)`: AS C, nearer the
origin, has an ASPA that does not list P, the next AS toward you.

!!! tip
    Run `raven watch --posture path-suspect` in a spare terminal during an
    incident. It shows leaked routes the moment RAVEN validates them.

---

## raven aspa

Show ASPA records for a specific ASN from the local ASPA store.

```bash
raven aspa --asn 13335
raven aspa --asn 13335 --format json
```

**Flags:**

| Flag | Description |
|---|---|
| `--asn` | ASN to look up (required) |
| `--format` | Output format: `table` or `json` |

**Example output:**

```text
ASPA RECORD — AS13335
─────────────────────────────────
Provider set (3):
AS174
AS1299
AS3356
```

If the ASN has no ASPA record in the current RTR cache, RAVEN will say so.

---

## raven aspa recommend

Analyse observed AS_PATHs from your BMP feeds and suggest which ASPA objects
your neighbours should create. Based on heuristics — verify with your peers
before acting on suggestions.

```bash
raven aspa recommend
raven aspa recommend --peer 192.168.1.1
raven aspa recommend --asn 64500
raven aspa recommend --min-observations 10
raven aspa recommend --top 20
raven aspa recommend --format json
```

**Flags:**

| Flag | Description |
|---|---|
| `--peer` | Restrict analysis to routes from a specific peer IP |
| `--asn` | Show suggestions for a specific customer ASN |
| `--min-observations` | Minimum route observations to include a relationship (default: 1) |
| `--top` | Show top N suggestions, default 20 (0 = all) |
| `--include-existing` | Include ASNs that already have complete ASPA coverage |
| `--format` | Output format: `table` or `json` |

**Example output:**

```text
ASPA OBJECT RECOMMENDATIONS (3)
Note: heuristic — based on observed AS_PATHs only. Verify with your peers.
┌─ AS64500  [no ASPA record]  confidence: 80%  observations: 1423
│  SUGGESTED PROVIDER    OBSERVED      STATUS
│  AS1299                892 routes    ✗ MISSING
│  AS3356                531 routes    ✗ MISSING
└──────────────────────────────────────────────────
┌─ AS64501  [existing ASPA (1 providers)]  confidence: 70%  observations: 203
│  SUGGESTED PROVIDER    OBSERVED      STATUS
│  AS174                 203 routes    ✗ MISSING
│  AS1299                203 routes    ✓ in ASPA
└──────────────────────────────────────────────────
```

**Confidence score** is a heuristic based on observation count and provider
count. Higher is more reliable. Scores above 70% are generally trustworthy.
Always verify with your peers before creating ASPA objects.

---

## raven what-if

Simulate the impact of deploying routing security policies without changing
anything on your routers.

### --reject-invalid

Simulate deploying reject-invalid ROV policy:

```bash
raven what-if --reject-invalid
raven what-if --reject-invalid --peer 192.168.1.1
raven what-if --reject-invalid --format json
```

**Example output:**

```text
REJECT-INVALID IMPACT SUMMARY
─────────────────────────────────────────────────
Routes currently received:     1044293
Routes that would be rejected: 2341 (0.22%)
Prefixes affected:             1892
Unique origin ASNs affected:   487
Carrying BLACKHOLE (RFC 7999): 37 routes, 21 prefixes

REJECTED BY ROV REASON
REASON           ROUTES   PREFIXES
invalid_length   2104     1702
invalid_origin   219      176
invalid_as0      12       9
invalid_as_set   6        5

TOP AFFECTED ORIGIN ASNs
ORIGIN ASN   ROUTES   PREFIXES   REASON
AS64666      142      61         invalid_origin
AS64667      89       44         invalid_length
AS64668      71       35         invalid_length (68), invalid_origin (3)
```

Rejected routes are broken down by [ROV reason](#rov-reasons): routes, and
the distinct prefixes they are for. `invalid_length` is usually most of
them: more-specifics announced by the right AS beyond their ROA's
maxLength, often traffic engineering or DDoS-mitigation /32s and /128s.
The BLACKHOLE line counts rejected routes that carry the BLACKHOLE
community (`65535:666`, RFC 7999): remote-triggered blackhole requests,
typically host routes, which a reject-invalid policy would drop before your
blackhole policy sees them. Accept them ahead of ROV in your import policy
if you honour them.

`REASON` in the top-origins table lists the origin's reason codes, most
common first, with counts when there is more than one. `PREFIXES` is the
origin's distinct rejected prefixes; earlier releases repeated the route
count there and showed one route's reason for the whole origin.

`--format json` gives the same breakdowns as `by_reason`
(`{reason_code, route_count, prefix_count}`), `blackhole_routes` and
`blackhole_prefixes`, and for each top origin its `reason_code`,
`reason_codes` (counts by code) and `reason`, the `rov_reason` of one of its
routes with that code.

### --aspa-enforce

Simulate dropping all path-suspect routes:

```bash
raven what-if --aspa-enforce
raven what-if --aspa-enforce --format json
```

**Example output:**

```text
ASPA ENFORCEMENT IMPACT SUMMARY
─────────────────────────────────────────────────
Routes currently received:     1,044,293
Routes with path-suspect:      12 (0.00%) ← would be dropped
Routes with no ASPA coverage:  891,203 (85.3%) ← unverifiable today
Prefixes affected:             10
Unique origin ASNs affected:   8
TOP FAILING AS_PATH HOPS
CUSTOMER ASN    UNAUTH PROVIDER  ROUTES AFFECTED
AS3356          AS7018           8
AS1299          AS3257           4
```

**Flags:**

| Flag | Description |
|---|---|
| `--reject-invalid` | Simulate reject-invalid ROV policy |
| `--aspa-enforce` | Simulate ASPA enforcement policy |
| `--peer` | Restrict simulation to routes from a specific peer |
| `--format` | Output format: `table` or `json` |

---

## raven version

Show RAVEN version and build information.

```bash
raven version
```

```text
raven version v0.1.0 (commit: abc1234, built: 2026-04-15T00:00:00Z)
```

---

## raven audit

Generate a read-only security posture report for a router. Shows ROV/ASPA
coverage, per-peer posture breakdown, top offending ASNs, and actionable
recommendations.

```bash
raven audit --router 198.51.100.1
raven audit --router 198.51.100.1 --format json
raven audit --router 198.51.100.1 --format markdown
raven audit --router 192.0.2.3 --rib loc-rib
```

**Flags:**

| Flag | Description |
|---|---|
| `--router` | The address to audit (required): a BGP peer's address, or for `--rib loc-rib`, the monitored router's address, since a Loc-RIB has no peer address |
| `--rib` | The one RIB to audit: `adj-rib-in-pre` (default, or `pre-policy`), `adj-rib-in-post` (or `post-policy`), `loc-rib`, `adj-rib-out-pre` or `adj-rib-out-post` |
| `--format` | Output format: `table`, `json`, or `markdown` |

`raven audit` reports on one RIB, so a router that sends several RIBs never
has its routes counted twice; v0.4.0 added every RIB up. The API takes the
same parameters, `/api/v1/audit?router=192.0.2.3&rib=loc-rib`. An unknown
RIB is an HTTP 400, which `raven audit` reports:

```text
Error: audit: unknown RIB "bogus": want adj-rib-in-pre (or pre-policy), adj-rib-in-post (or post-policy), loc-rib, adj-rib-out-pre or adj-rib-out-post
```

**Example output**, for the Loc-RIB of `rr1` in the
[`raven routes`](#raven-routes) example:

```text
  ROUTER AUDIT REPORT
  ─────────────────────────────────────────────────
  Router ID:     192.0.2.3
  RIB:           loc-rib
  Generated At:  2026-10-20 01:55:01 UTC
  Total Routes:  3
  ROV Coverage:  100.0%
  ASPA Coverage: 0.0%

  POSTURE SUMMARY
  POSTURE          COUNT   %
  origin-only      2       66.7%
  origin-invalid   1       33.3%

  PEERS
  PEER                   ASN       ROUTES   ROV    ASPA
  loc-rib of 192.0.2.3   AS64499   3        100%   0%

  TOP OFFENDERS
  ORIGIN ASN   COUNT   WORST POSTURE    EXAMPLE PREFIXES
  AS64499      1       origin-invalid   2001:db8:ffff::1/128

  RECOMMENDATIONS
  1. 1 origin-invalid route(s) detected — consider deploying a reject-invalid ROV policy to drop these.
  2. No ASPA coverage detected — enable an RTR v2 cache to start AS Path Validation.
```

The `PEERS` table has one row per router, instance and peer address: a
peer in a VRF adds ` rd ` and its route distinguisher, and a Loc-RIB row
reads `loc-rib of` and the router's address. The JSON report names the
RIB in `rib`, and each `peers` entry carries `router` and
`peer_distinguisher` (always present, `""` for the global instance):

```json
{
  "router_id": "192.0.2.3",
  "rib": "loc-rib",
  ...
  "peers": [
    {
      "router": "192.0.2.3",
      "peer_addr": "0.0.0.0",
      "peer_distinguisher": "",
      "peer_asn": 64499,
      "total_routes": 3,
      ...
    }
  ],
  ...
}
```

The top offender here is the router's own AS: the `origin-invalid` route
is `rr1`'s loopback, which is more specific than its ROA allows. A Loc-RIB
audit counts your internal routes, so read its `origin-invalid` routes and
its recommendation to reject invalids with that in mind; see
[Internal routes show as Invalid](../troubleshooting.md#internal-routes-show-as-invalid).


!!! tip
    Run `raven audit` weekly in a cron job with `--format json` to track
    your security posture over time. Use `--format markdown` for NOC reports
    and incident post-mortems.

---

## raven check stealthy

Detects stealthy BGP hijacks by comparing the control-plane BMP RIB view
against actual data-plane forwarding using probes. A diverging first-hop ASN
indicates traffic is being routed through a different network than BGP
advertises — invisible to the control plane alone.

```bash
raven check stealthy --prefix 203.0.113.0/24
raven check stealthy --prefix 203.0.113.0/24 --probe-via clab-raven-demo-edge
raven check stealthy --prefix 203.0.113.0/24 --probe-count 5 --timeout 5s
raven check stealthy --prefix 203.0.113.0/24 --format json
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--prefix` | required | Prefix to probe (CIDR) |
| `--probe-count` | 3 | Number of probes to send |
| `--timeout` | 3s | Probe timeout per probe |
| `--probe-via` | — | Run traceroute from inside a Docker container (for topologies where the host is outside BGP forwarding) |
| `--format` | table | Output format: `table` or `json` |

**Verdicts:**

| Verdict | Meaning |
|---|---|
| `CLEAN` | Data-plane first hop matches BMP RIB expected AS |
| `STEALTHY HIJACK DETECTED` | First hop AS differs from BMP RIB — traffic diverted |
| `DIVERGENCE` | First hop not in BMP peer table — unconfirmed divergence |
| `INCONCLUSIVE` | All probes timed out |

The expected AS is the neighbor the router learned the route from: the
BMP peer's AS, or for a Loc-RIB route, which has no peer, the first AS of
its AS_PATH after any leading copy of the router's own AS. A Loc-RIB
instance is never matched as the BGP neighbor a probe reached.
`raven check global` reports a Loc-RIB route's neighbor AS the same way.

**Example — clean baseline:**

```text
$ raven check stealthy --prefix 203.0.113.0/24 --probe-via clab-raven-demo-edge
Checking control/data-plane divergence for 203.0.113.0/24...
Control plane (BMP/RIB):
  Route    : 203.0.113.0/24 via AS65000 (origin-only)
  RIB state: CLEAN — ROV Valid, no path violations
Data plane probe (traceroute from clab-raven-demo-edge to 203.0.113.1):
  Probe 1  : TTL-exceeded at 10.0.0.1 (AS65000 — expected)
  Probe 2  : TTL-exceeded at 10.0.0.1 (AS65000 — expected)
  Probe 3  : TTL-exceeded at 10.0.0.1 (AS65000 — expected)
╔══════════════════════════════════════════════════════╗
║ CLEAN: Data-plane path matches BMP RIB               ║
║ RIB says: AS65000 │ Traffic goes to: AS65000         ║
╚══════════════════════════════════════════════════════╝
```

**Example — stealthy hijack detected:**

```text
$ raven check stealthy --prefix 203.0.113.0/24 --probe-via clab-raven-demo-edge
Checking control/data-plane divergence for 203.0.113.0/24...
Control plane (BMP/RIB):
  Route    : 203.0.113.0/24 via AS65000 (origin-only)
  RIB state: CLEAN — ROV Valid, no path violations
Data plane probe (traceroute from clab-raven-demo-edge to 203.0.113.1):
  Probe 1  : TTL-exceeded at 10.0.3.2 (AS65099 — ATTACKER)
  Probe 2  : TTL-exceeded at 10.0.3.2 (AS65099 — ATTACKER)
  Probe 3  : TTL-exceeded at 10.0.3.2 (AS65099 — ATTACKER)
╔═════════════════════════════════════════════════════════╗
║ STEALTHY HIJACK DETECTED: control/data-plane divergence ║
║ RIB says: AS65000 │ Traffic goes to: AS65099            ║
╚═════════════════════════════════════════════════════════╝
```

**Note on permissions:** Raw ICMP requires `CAP_NET_RAW` or root. Grant it
without sudo:

```bash
sudo setcap cap_net_raw=eip ./raven
```

If ICMP fails, RAVEN automatically falls back to TCP SYN probes on port 80.
Use `--probe-via` to run probes from inside a container that is part of the
BGP topology.

---

## raven check global

Correlates a prefix's local BMP-observed origin against the origin ASNs that
third-party route collectors see for it, via the
[RIPEstat looking-glass data call](https://stat.ripe.net/docs/02.data-api/looking-glass.html).

RAVEN's ROV and ASPA validation is local-vantage-point only: it knows what
your own BMP-attached routers received. That cannot tell you whether a
suspicious route is a real hijack the rest of the internet also sees, or a
purely local leak or misconfiguration. This check answers that question.

```bash
raven check global --prefix 203.0.113.0/24
raven check global --prefix 203.0.113.0/24 --origin-asn 64511
raven check global --prefix 203.0.113.0/24 --format json
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--prefix` | required | Prefix to correlate (CIDR) |
| `--origin-asn` | — | Origin ASN to compare against. Defaults to the daemon's BMP-observed origin for the prefix |
| `--format` | table | Output format: `table` or `json` |

**Verdicts:**

| Verdict | Meaning |
|---|---|
| `MATCH` | The local origin is the single most-observed origin globally — the route looks the same from outside |
| `DIVERGENT` | The world's majority origin is not the local origin, or the local origin is only tied for most-observed (a MOAS conflict) |
| `LOCAL_ONLY` | No collector sees this prefix at all — points at a local leak or misconfiguration, not a propagated hijack |
| `INCONCLUSIVE` | The query failed, timed out, returned malformed data, or there was no local origin to compare against |

`MATCH` requires a strict majority. A tie between the local origin and
another ASN is reported as `DIVERGENT`: a MOAS conflict at equal global
visibility still warrants a look.

**Example — global match:**

```text
$ raven check global --prefix 8.8.8.0/24
Correlating global visibility for 8.8.8.0/24...

Local view (BMP/RIB):
  Route   : 8.8.8.0/24 via AS15169 (secured)
  Peer    : 10.0.0.1 (AS65000), 1 route(s) in RIB
  Local   : ROV Valid, ASPA Valid

Global view (RIPEstat looking-glass, https://stat.ripe.net):
  ORIGIN   COLLECTOR PEERS  SHARE  NOTE
  AS15169  368              100%   matches local
  368 collector peer observations in 608ms

╔═══════════════════════════════════════════════════════════════════════════════════╗
║ GLOBAL MATCH: Global majority origin matches local BMP view (368 collector peers) ║
║ Local RIB says: AS15169 │ The internet says: AS15169                              ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
```

**Example — global divergence (the hijack is real and propagated):**

```text
$ raven check global --prefix 203.0.113.0/24
Correlating global visibility for 203.0.113.0/24...

Local view (BMP/RIB):
  Route   : 203.0.113.0/24 via AS64511 (origin-invalid)
  Peer    : 10.0.3.2 (AS65099), 1 route(s) in RIB
  Local   : ROV Invalid, ASPA Unknown

Global view (RIPEstat looking-glass, https://stat.ripe.net):
  ORIGIN   COLLECTOR PEERS  SHARE  NOTE
  AS65000  18               82%
  AS64511  4                18%    matches local
  22 collector peer observations in 512ms

╔════════════════════════════════════════════════════════════════════════════════════════╗
║ GLOBAL DIVERGENCE DETECTED: MOAS conflict — 2 origins seen globally, most-observed ...  ║
║ Local RIB says: AS64511 │ The internet says: AS65000                                    ║
╚════════════════════════════════════════════════════════════════════════════════════════╝
```

**Example — local-only route (a leak, not a hijack):**

```text
$ raven check global --prefix 203.0.113.0/24 --origin-asn 64511
Global view (RIPEstat looking-glass, https://stat.ripe.net):
  no observations — no route collector carries this prefix

╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ LOCAL-ONLY ROUTE: No collector sees this prefix — a local leak or misconfiguration, not a propagated hijack  ║
║ Local RIB says: AS64511 │ The internet says: nobody                                                         ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
```

**Notes:**

- The looking-glass call is **exact-match**. A more-specific prefix that no
  collector carries returns no observations, which is exactly the
  `LOCAL_ONLY` signal — not a query failure.
- **Collector peers, not collectors.** Counts are in units of one
  (route collector, peer address) pair, so a single RIS collector peering
  with 30 networks contributes up to 30 observations.
- This command reads `external.ripestat` from `raven.yaml` for the base URL,
  timeout, cache TTL and rate limit, but does **not** require
  `external.ripestat.enabled: true` — invoking it is itself the explicit
  opt-in. The `enabled` flag gates only the Event Engine's automatic
  correlation. See
  [Configuration → External Correlation](configuration.md#external-correlation-ripestat).
- Without `--origin-asn` the baseline comes from the daemon's RIB, so
  `raven serve` must be reachable. With `--origin-asn` the check works
  against no daemon at all.
- It is **fail-open**: an unreachable or malformed RIPEstat degrades to
  `INCONCLUSIVE` and exits 0. The result is a standalone annotation and does
  not change the route's [security posture](security-postures.md).

---

## raven flowspec list

Show all active Flowspec mitigation rules in RAVEN's registry. Displays
the rule key, action, dry-run state, remaining TTL, and insertion time.

```bash
raven flowspec list
raven flowspec list --format json
```

**Flags:**

| Flag | Description |
|---|---|
| `--format` | Output format: `table` or `json` |

**Example output:**

```text
RAVEN Flowspec Rules
════════════════════════════════════════════════════════
KEY                            ACTION  DRY-RUN  TTL        INSERTED
192.0.2.0/24|drop              drop    yes      4m50s      2026-05-06 14:23:01
10.10.0.0/24|drop              drop    yes      3m55s      2026-05-06 14:24:23
2 active rules  (dry-run mode — no live injection)
```

Rules are created automatically by the Event Engine when a route matches
a configured `flowspec` action. Rules in `dry-run` mode are tracked but
not injected into GoBGP until toggled live with `raven flowspec toggle`.

---

## raven flowspec toggle

Toggle a Flowspec rule between dry-run and live GoBGP injection. When
toggled to live, RAVEN calls GoBGP's AddPath API to inject the rule.
Toggle again to withdraw and return to dry-run.

```bash
raven flowspec toggle "192.0.2.0/24|drop"
```

**Arguments:**

| Argument | Description |
|---|---|
| `<key>` | Rule key as shown in `raven flowspec list` (required) |

**Example — toggling to live:**

```text
Rule: 192.0.2.0/24|drop
Dry-run: yes → LIVE
⚠  Live injection enabled. Flowspec rule is now active in GoBGP.
Run 'raven flowspec toggle "192.0.2.0/24|drop"' again to
withdraw and return to dry-run mode.
```

**Example — withdrawing:**

```text
Rule: 192.0.2.0/24|drop
Dry-run: LIVE → yes (withdrawn from GoBGP)
```

!!! warning
    Live injection sends a Flowspec route to GoBGP which will propagate
    it to any configured BGP peers. Only toggle to live when you intend
    to apply the mitigation. The rule will auto-expire after the
    configured TTL (default: 5 minutes).

---

## raven rtr

Parent command group for RTR (RPKI-to-Router) cache session tools. It has no
action of its own — run it bare to list the subcommands.

```bash
raven rtr
```

**Subcommands:**

| Command | Description |
|---|---|
| `raven rtr monitor` | Observe one or more RTR cache sessions, log telemetry to NDJSON, detect anomalies, and compare caches |
| `raven rtr seed-baseline` | Build an anomaly-detector baseline snapshot from recorded telemetry |

These commands are **standalone** — they connect directly to an RTR cache and
do not require a running `raven serve` daemon or a config file.

---

## raven rtr monitor

Connect to one or more RTR caches, record session lifecycle and sync events
as NDJSON, and run the adaptive anomaly detector over the sync stream. It
keeps an in-memory VRP/ASPA set per cache — no BMP ingestion or route
validation happens here. Every setting comes from flags; no config file is
read.

```bash
raven rtr monitor --cache localhost:3323 --log-file rtr-telemetry.ndjson
raven rtr monitor --cache rpki.example.com:3323 --transport tls
raven rtr monitor --log-file /tmp/rtr.ndjson --prometheus :9595
raven rtr monitor --anomaly-snapshot ~/.raven/anomaly-baseline.json --prometheus :9595
raven rtr monitor --cache routinator.example.net:3323 --cache fort.example.net:323 --cache rpki-client.example.net:8282
```

Runs in the foreground until you press Ctrl+C.

**Output:** the NDJSON written to `--log-file` is a versioned contract: every
record type, field and value is documented in
[Telemetry NDJSON](../reference/telemetry-ndjson.md), with a JSON Schema and
the compatibility policy. Build parsers against that page.

**Running instance:** [ASPA Explorer](https://aspa.ping6.it/statistics.html#rtr-title), a public service of the Department of Information Engineering at the University of Padova, runs `raven rtr monitor` against its own Routinator and Fort validators and several public RTR servers, and publishes a summary of the telemetry every five minutes (also available as [JSON](https://aspa.ping6.it/api/v1/rtr.json)).

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--cache` | `localhost:3323` | RTR cache address. Repeat to monitor several caches in one process and compare them (see below); each gets its own session, data set, anomaly baseline and NDJSON records |
| `--compare-settle` | `0` (automatic) | With several caches: how long a difference between them must last before it is reported. Automatic: twice the slowest cache's median refresh interval, at least `10m`, and `30m` until every cache's interval is known |
| `--log-file` | `rtr-telemetry.ndjson` | Path to the NDJSON telemetry output file (created if absent, appended if present) |
| `--transport` | `tcp` | RTR transport: `tcp` or `tls` |
| `--rtr-version` | `auto` | RTR protocol version. `auto` starts at 2 and falls back one version at a time (2, 1, 0) when the cache rejects one with Error Report code 4 or closes the connection before answering; `0`, `1` or `2` pins the session to that version, with no fallback and no re-probe |
| `--prometheus` | — | Prometheus listen address (e.g. `:9595`); empty disables the metrics endpoint |
| `--anomaly-snapshot` | `~/.raven/anomaly-baseline.json` | Path to the adaptive anomaly-detector baseline snapshot (JSON) |

**Anomaly detection:**

- The detector **warm-starts** from the baseline snapshot at `--anomaly-snapshot`
  if one exists. A missing or unreadable snapshot degrades to a cold start —
  it never blocks startup. Seed a snapshot ahead of time with
  `raven rtr seed-baseline` to skip the live warm-up.
- Each incremental sync is scored against rolling per-metric windows
  (`interval_since_ns`, `sync_duration_ns`, `vrp_announced`, `vrp_withdrawn`,
  `aspa_announced`, `aspa_withdrawn`) using median/MAD adaptive thresholds.
- **Full resyncs are recorded but not evaluated** — a full table dump reports
  nearly the entire VRP/ASPA set as "announced", which is not comparable to
  incremental deltas and would trip a false positive.
- When an anomaly fires it is written to the NDJSON sink as an `anomaly` record
  and, if `--prometheus` is set, increments `raven_rtr_anomaly_total{cache,severity}`
  and sets `raven_rtr_anomaly_last_timestamp{cache}`. See
  [Observability & Metrics](observability.md) for the metric reference.
- The baseline is saved periodically and again on graceful shutdown, so a
  restarted monitor resumes from where it left off.

**Comparing several caches:** with more than one `--cache`, the monitor
compares the caches' VRP and ASPA sets after every sync, to tell a problem
upstream of every validator (every cache loses the same objects at once)
from a problem at one validator (stuck, behind, misconfigured):

- A cache that persistently disagrees with the others (longer than the
  settle window) gets one `divergence` record for the episode, saying per
  kind how many VRPs or ASPA customers it is **missing** (the majority has
  them), has **extra** (only a minority has them), or is **split** on (no
  majority, as with two caches), with up to 20 samples; and one
  `divergence_resolved` when it agrees again. Caches below RTR version 2 are
  compared on VRPs only, and a disconnected cache is left out until it
  syncs again.
- The same large change (one that trips the anomaly detector) at every
  cache within the settle window is one `upstream_change` record, alongside
  each cache's `anomaly`. A large change at one cache only is never called
  upstream.
- `upstream_change` needs a warmed-up anomaly detector at every compared
  cache: 100 incremental syncs each (about 17 hours at a 10-minute refresh
  interval), unless `--anomaly-snapshot` holds a baseline for each `--cache`
  or one was seeded with `raven rtr seed-baseline`. After a fresh start, a
  real upstream event shows only as per-cache `anomaly` records.
- Caches with different Trust Anchor sets or local exceptions (SLURM) hold
  different data on purpose and show a standing divergence that never
  resolves, by design.
- Memory: about 316 MB per cache at 1M VRPs, of which about 80 MB is the
  comparison's copy of the cache's set (the rest is the VRP store the
  session needs anyway).
- With `--prometheus`, `raven_rtr_divergent_items{cache,kind}` is the
  number of items each cache persistently disagrees on, and
  `raven_rtr_compared{cache}` is 1 while the cache is in the comparison.
  The item counts keep their last values while a cache is out of it; see
  [Observability](observability.md) for an alert that joins the two.

The details are in
[Telemetry NDJSON → Comparing caches](../reference/telemetry-ndjson.md#comparing-caches).
With a single `--cache` none of this runs and the output is as before.

**Watching for anomalies live:**

```bash
tail -f rtr-telemetry.ndjson | grep '"event_type":"anomaly"'
tail -f rtr-telemetry.ndjson | grep -E '"event_type":"(divergence|divergence_resolved|upstream_change)"'
```

---

## raven rtr seed-baseline

Replay a recorded NDJSON telemetry file through the anomaly detector's rolling
windows and write the resulting baseline snapshot. Run it once against an
existing collection to produce a reusable baseline that
`raven rtr monitor --anomaly-snapshot` loads on startup, skipping the live
warm-up period.

```bash
raven rtr seed-baseline --input rtr-baseline.ndjson
raven rtr seed-baseline --input rtr-baseline.ndjson --output ~/.raven/anomaly-baseline.json
```

Only **sync** records populate the windows; connected/disconnected and
structural (reset/error) records are ignored, and full syncs are skipped. The
input is treated as ground-truth-normal, so no anomalies are reported during
seeding.

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--input` | required | Path to the recorded NDJSON telemetry file to seed from |
| `--output` | `~/.raven/anomaly-baseline.json` | Path to write the baseline snapshot to |

**Example output:**

```text
lines processed: 40320
sync records:    1342 (7 full syncs skipped)
window fill levels for localhost:3323:
  interval_since_ns: 500/500 (full)
  sync_duration_ns:  500/500 (full)
  vrp_announced:     500/500 (full)
  vrp_withdrawn:     500/500 (full)
  aspa_announced:    500/500 (full)
  aspa_withdrawn:    500/500 (full)
output: /home/user/.raven/anomaly-baseline.json
```

A window that reaches its cap (500 samples) reports `(full)` — the detector has
a complete baseline for that metric. Partially-filled windows still work but
give the detector less history to reason about.

!!! tip
    The typical workflow is: record telemetry with `raven rtr monitor` over a
    representative period, run `raven rtr seed-baseline` against that file once,
    then start the live monitor with `--anomaly-snapshot` pointed at the seeded
    baseline so it detects from the first sync.
