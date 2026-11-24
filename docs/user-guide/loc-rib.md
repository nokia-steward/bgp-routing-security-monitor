# Loc-RIB Monitoring

BMP Loc-RIB monitoring ([RFC 9069](https://www.rfc-editor.org/rfc/rfc9069.html)) lets a router export its Loc-RIB: the routes it accepted and selected as best, one per prefix, whichever peer they came from or whether it originated them itself. RAVEN stores a router's Loc-RIB apart from its Adj-RIB-In and validates every route in it, so you see the security posture of the paths your network actually uses.

## Loc-RIB or pre-policy Adj-RIB-In

The two answer different questions:

| | Adj-RIB-In pre-policy | Loc-RIB |
|---|---|---|
| What it holds | Every route each peer sent, before import policy | The router's best path for each prefix, after import policy and best-path selection |
| Shows attacks your import policy already drops | Yes | No |
| Shows the routes the router uses for forwarding | Not on its own | Yes |
| Includes routes the router originates, and routes learned over iBGP | Only from monitored iBGP peers | Yes |
| Size | One table per peer | One table per router |

Use the Loc-RIB when you want to know whether the routes in use are secure, for example whether an `origin-invalid` route got past your import policy and became a best path, or when exporting every peer's pre-policy table is too much for the router or for RAVEN. Use pre-policy when you want to see everything your peers send, including what your policy filters. Many networks export both; RAVEN keeps them apart and shows both by default.

## What RAVEN shows

**RIBs.** RAVEN names each RIB the same way everywhere (CLI, API, metrics, audit, event triggers): `adj-rib-in-pre`, `adj-rib-in-post`, `loc-rib`, `adj-rib-out-pre`, `adj-rib-out-post`. Where you name a RIB, `pre-policy` and `post-policy` are accepted as aliases of `adj-rib-in-pre` and `adj-rib-in-post`.

**The default view.** Without a RIB, route queries return the default view, `adj-rib-in-pre` plus `loc-rib`: `raven routes`, `raven watch`, `raven validate`, `/api/v1/routes`, `/api/v1/watch`. So does `raven status`, whose header names the view. A router that sends only its Loc-RIB shows its routes, and a prefix a router reports in both RIBs is listed once per RIB. `raven what-if` and `raven aspa recommend` use Adj-RIB-In pre-policy routes only: they answer a question about what neighbors sent, and a route in both RIBs would otherwise count twice.

**Choosing RIBs.** `--rib` on [`raven routes`](cli-reference.md#raven-routes) and [`raven watch`](cli-reference.md#raven-watch), and the API's `rib` parameter, take one or more RIBs, comma-separated:

```bash
raven routes --rib loc-rib
raven routes --rib loc-rib,adj-rib-in-pre --prefix 203.0.113.0/24
raven watch --rib loc-rib --posture origin-invalid
curl -s 'http://127.0.0.1:11020/api/v1/routes?rib=loc-rib'
```

**The Loc-RIB instance as a peer.** RFC 9069 sends Loc-RIB routes under a per-peer header of peer type 3 with the zero peer address, so RAVEN lists each Loc-RIB instance as a peer of type `loc-rib`. `raven peers` and `raven status` have a `TYPE` column and show the instance as `loc-rib` in `PEER`. Both show its `ASN`; `raven peers` also shows its `ROUTER ID`. Both values are the router's own:

```text
ROUTER  PEER          TYPE     ASN    ROUTER ID     STATE  ROUTES  UP SINCE
rr1     198.51.100.7  global   64500  198.51.100.7  up     1       2026-10-18T09:12:44Z
rr1     loc-rib       loc-rib  64499  192.0.2.3     up     3       2026-10-18T09:12:44Z
```

A VRF's Loc-RIB shows its route distinguisher, as in `loc-rib rd 64499:100`. In `/api/v1/peers` and in the `bmp_peers` array of `/api/v1/status`, a Loc-RIB instance has `peer_type` `loc-rib`, `addr` `0.0.0.0` and a `table_name`, the VRF/Table Name from its Peer Up. The default instance is `global`, as RFC 9069 §5.2.1 names it, whether or not its Peer Up carries the name, and whether or not it sends a Peer Up at all.

**Routes.** `raven routes` has a `RIB` column, and a Loc-RIB route shows `-` as its peer, since it is the router's own selection:

```text
PREFIX                    ROUTER  PEER          RIB             ORIGIN   ROV      ASPA     POSTURE
203.0.113.0/24            rr1     198.51.100.7  adj-rib-in-pre  AS64502  Valid    Unknown  origin-only
2001:db8:ffff::1/128      rr1     -             loc-rib         AS64499  Invalid  Unknown  origin-invalid
2001:db8:100::/48         rr1     -             loc-rib         AS64499  Valid    Unknown  origin-only
203.0.113.0/24            rr1     -             loc-rib         AS64502  Valid    Unknown  origin-only
```

In JSON, a Loc-RIB route has `peer_type` `loc-rib`, `peer` `0.0.0.0` and the router's own AS as `peer_asn`. See [`raven routes`](cli-reference.md#raven-routes) for every field.

## Origin validation of your own routes

The Loc-RIB also holds routes that no eBGP peer sent to this router: prefixes the router originates, and routes it learned over iBGP from routers in its own AS. A locally originated route has an empty AS_PATH, so RFC 6811 §2 makes its origin the router's own AS. An iBGP-learned route normally keeps the AS_PATH from the border router that learned it, and its origin is the last AS in that path; if that path is empty, the origin is the router's own AS. RAVEN validates both against your ROAs like any other route. RAVEN takes the router's AS from the Loc-RIB per-peer header's Peer AS, which RFC 9069 sets to it, so a locally originated route works with or without a Peer Up, and after a restart from a snapshot. Inside a confederation, RAVEN uses the confederation identifier when it can tell it; see [The origin AS](../architecture/validation-engine.md#the-origin-as).

In the example above, `2001:db8:100::/48` is a prefix `rr1` originates, `Valid` under its ROA for `2001:db8::/32` (maxLength 48):

```text
matches VRP {2001:db8::/32, AS64499, /48}; origin is the router's own AS: empty AS_PATH (RFC 6811 §2)
```

!!! note "Expect internal routes to be Invalid"
    `2001:db8:ffff::1/128`, a loopback learned over iBGP, is `origin-invalid`: it is more specific than the ROA's maxLength. Loopbacks and link subnets often are. This is correct, and harmless as long as those prefixes are not announced outside your network. Keep them out of alerts rather than loosening your ROAs; see [Internal routes show as Invalid](../troubleshooting.md#internal-routes-show-as-invalid).

Some routers put their own AS first in every Loc-RIB AS_PATH (FRR 10.2 does), so a route they originate arrives with a path of just their AS. A Loc-RIB path holding only the router's own AS counts as empty for the origin, so these routes are validated the same way.

## ASPA on Loc-RIB routes

ASPA verification needs the procedure for the neighbor a route came from (see [How RAVEN chooses the procedure](../getting-started/concepts.md#how-raven-chooses-the-procedure)). A Loc-RIB route has no neighbor address, so RAVEN works from its AS_PATH:

1. A leading copy of the router's own AS, as FRR 10.2 sends, is removed (every copy, if prepended). RAVEN verifies the path without it; the stored route keeps its path as received.
2. The neighbor AS is the first AS left in the path.
3. The procedure comes from an [`aspa-peers`](configuration.md#validationaspa-peers) `asn` entry for that AS, then from `aspa-default-procedure`. `aspa_procedure_source` is `config-asn` or `default`. `address` entries never match a Loc-RIB route.
4. The neighbor-AS check does not apply: the neighbor AS is taken from the path, so the check could not fail.

For example, with this configuration, a Loc-RIB route whose AS_PATH is `64499 64500 64502` on router AS64499 is verified as `64500 64502`, with the `downstream` procedure from the `config-asn` entry for AS64500:

```yaml
validation:
  aspa-peers:
    - asn: 64500
      neighbor-role: provider
```

!!! warning "Limitation: best paths learned over iBGP"
    For a best path learned over iBGP, the first AS of the path is the neighbor of the border router that learned it from outside, not a neighbor of the monitored router. RAVEN chooses the procedure for that AS all the same, which is right when your `aspa-peers` entries describe the AS's relationship to your network as a whole, and wrong when the same AS is a provider at one border and a customer at another.

A route with an empty AS_PATH, or one holding only the router's own AS, is not verified: its ASPA state is `Unknown`, with the reason `not ASPA-verified: empty AS_PATH; the route is locally originated or iBGP-learned without an AS_PATH`.

Every route's ASPA state is also `Unknown` while RAVEN has no ASPA data, until an RTR cache syncs at protocol version 2 (reason `no ASPA data (no RTR v2 session)`), and always with `validation.aspa: false` (reason `ASPA disabled`). See [ASPA without ASPA data](../architecture/validation-engine.md#aspa-without-aspa-data).

## Router configuration

### FRR

Under `router bgp`, a BMP target monitors the Loc-RIB with `bmp monitor <afi> <safi> loc-rib`:

```text
router bgp 64499
 bmp targets raven
  bmp monitor ipv4 unicast loc-rib
  bmp monitor ipv6 unicast loc-rib
  bmp connect 192.0.2.10 port 11019 min-retry 1000 max-retry 5000
 exit
exit
```

Add `bmp monitor ipv4 unicast pre-policy` (and IPv6) to the same target to export both. The lab covers IPv4 unicast only. This syntax was checked against FRR 10.7.1, which the lab's `rr1` runs (see the [Loc-RIB lab](../lab/loc-rib.md)). FRR's Loc-RIB behavior differs between releases:

| | FRR 10.2.5 | FRR 10.7.1 |
|---|---|---|
| Loc-RIB Peer Up | Not sent | Sent, and a Peer Up for each BGP neighbor too |
| AS_PATH of Loc-RIB routes | The router's own AS first | As received |
| Loc-RIB update after a best-path change | Not sent | Sent |
| Loc-RIB withdrawal when a prefix is withdrawn | Not tested | Sent |
| Loc-RIB withdrawal when a BGP session on the router goes down | Not tested | Not tested |

FRR 10.7.1's Peer Ups for its BGP neighbors make RAVEN list them as peers (type `global`) with 0 routes, since only the Loc-RIB is monitored. With FRR 10.2, RAVEN's Loc-RIB can go stale after a best-path change; prefer a release that sends Loc-RIB updates.

### Other routers

Loc-RIB support and its configuration differ by vendor and release: some routers do not support RFC 9069 at all, and some send it with different defaults for the Peer Up, the AS_PATH or VRF instances. Check your router's documentation for BMP Loc-RIB (RFC 9069), then confirm with `raven peers` that a `loc-rib` peer appears for the router and with `raven routes --rib loc-rib --router <router>` that its routes arrive.

### Loc-RIB without a Peer Up

RFC 9069 has the router send a Peer Up for its Loc-RIB instance, but some routers, FRR 10.2 among them, send routes without one. RAVEN registers a Loc-RIB instance from its first Route Monitoring message that carries routes or withdrawals; an End-of-RIB alone does not register it. It does the same for an instance that sends routes after its Peer Down. Each registration is logged at INFO, here with `logging.format: text`:

```text
time=2026-10-18T09:12:44.047Z level=INFO msg="BMP Loc-RIB registered" subsystem=bmp router=192.0.2.3:51775 session=1 peer_up=false asn=64499 router_id=192.0.2.3 peer_distinguisher="" table_name=global filtered=false
```

`peer_up` is `true` when the instance registered from its Peer Up, and `filtered` reports the Loc-RIB's F flag (RFC 9069 §4.2: the router sends a filtered, not complete, Loc-RIB). The default instance is named `global` whether or not it sent a Peer Up; a VRF instance has no name without one.

A Loc-RIB Peer Up that is sent but wrong is worse than none. GoBGP before v4.8.0 always sends its Loc-RIB routes with ADD-PATH path IDs, but its Loc-RIB Peer Up advertises ADD-PATH only when multipath is enabled, and leaves the Peer BGP ID and Peer AS zero. RAVEN takes ADD-PATH from the Peer Up, so with GoBGP's default configuration it would read those prefixes 4 bytes out of step. GoBGP v4.8.0 fixed this ([osrg/gobgp#3500](https://github.com/osrg/gobgp/pull/3500)): use v4.8.0 or later. RAVEN's lab does not run GoBGP as a monitored router.

A Loc-RIB instance's Peer Down removes its Loc-RIB routes only, and a BGP peer's Peer Down removes that peer's Adj-RIB-In and Adj-RIB-Out routes only. When the BMP session ends, every route it sent is withdrawn and every peer's `raven_bmp_peer_state` goes to 0.

## Metrics, events and audit

- `raven_routes_total` and `raven_route_table_size` have a `rib` label, so Loc-RIB routes are counted under `rib="loc-rib"`. See [Observability & Metrics](observability.md#available-metrics) for the query changes.
- A Loc-RIB instance has its own `raven_bmp_peer_state` series, with `peer="0.0.0.0"`.
- The Event Engine evaluates Loc-RIB routes. A router that sends pre-policy and Loc-RIB fires a rule once per RIB; the cooldown is per route and RIB, and webhooks carry `rib`. Use a [`rib` trigger](active-response.md#rib-trigger) to alert on one RIB.
- `raven audit --router <router address> --rib loc-rib` audits a router's Loc-RIB. For `--rib loc-rib`, `--router` is the monitored router's address, since a Loc-RIB route's peer address is the zero address. See [`raven audit`](cli-reference.md#raven-audit).
