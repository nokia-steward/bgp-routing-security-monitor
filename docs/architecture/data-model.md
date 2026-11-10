# Data Model

This page describes how RAVEN turns BMP messages into routes, and how it
identifies and stores them. Knowing the route key explains why RAVEN shows
the same prefix from the same peer address more than once, and why its
counts match what your routers report.

## From BMP to routes

RAVEN decodes BMP and BGP itself. Its decoder in `internal/bmp` reads the
BMP messages your routers send and the BGP UPDATE and OPEN messages carried
inside them. RAVEN does not use GoBGP to parse UPDATEs; GoBGP appears in
RAVEN only as the Flowspec injection target for
[Active Response](../user-guide/active-response.md).

BMP input is untrusted: anything that reaches the BMP port can send it
bytes, so the decoder is written to fail safe and is fuzzed. `make fuzz` in
the code repository runs three fuzz targets, `FuzzBMPMessage`,
`FuzzPeerUpOpen` and `FuzzDecodeUpdate`, and every failing input found is
kept and replayed by the regular test suite. A BMP message longer than
1 MiB closes the session, Statistics Report entries are sized from the bytes
present rather than from the count the message claims, and the UPDATE's
Withdrawn Routes Length is checked against the message length.

The decoder handles:

- **Peer Up**: both the sent and received OPEN messages, including RFC 9072
  extended optional parameters. RAVEN reads the ADD-PATH capability from
  both OPENs to learn, per address family and direction, whether the peer's
  UPDATEs carry path identifiers.
- **Route Monitoring**: withdrawn routes, path attributes and NLRI in the
  UPDATE body (IPv4 unicast), and `MP_REACH_NLRI` / `MP_UNREACH_NLRI` for
  IPv4 and IPv6 unicast, including IPv6 next hops for IPv4 routes
  (RFC 8950). Other address families are counted in
  `raven_bmp_unsupported_nlri_total` and not stored.
- **AS_PATH**: two-octet AS_PATHs, as sent by a peer whose per-peer header
  has the A flag set, are merged with `AS4_PATH` (RFC 6793 §4.2.3), so the
  route carries the real four-octet path.
- **RIB type**: the per-peer header tells RAVEN whether a route is
  Adj-RIB-In pre-policy, Adj-RIB-In post-policy, Adj-RIB-Out pre- or
  post-policy (RFC 8671), or Loc-RIB (peer type 3, RFC 9069).
- **Loc-RIB**: a Loc-RIB per-peer header has the zero peer address, the
  router's own AS as its Peer AS, and only one flag, F (filtered), in the
  bit other peer types use for V (IPv6); RAVEN reads none of the Adj-RIB
  flags (V, L, A, O) on it. Its Peer Up's VRF/Table Name TLV names the
  instance, and the default instance (zero peer distinguisher) is `global`
  when the TLV is missing (RFC 9069 §5.2.1). A Loc-RIB instance that sends
  routes or withdrawals without a Peer Up, as FRR 10.2 does, or after its
  Peer Down, is registered as a peer from that message, with the same
  default name; an End-of-RIB alone does not register it. RAVEN logs the
  registration at INFO as `BMP Loc-RIB registered`, with `peer_up` true or
  false. A Loc-RIB Peer Down removes that Loc-RIB's routes only, and a BGP
  peer's Peer Down its Adj-RIB-In and Adj-RIB-Out routes only.

A malformed UPDATE is handled the way RFC 7606 tells your router to handle
it (attribute discard, treat-as-withdraw or session reset), so RAVEN's
table keeps matching the router's Adj-RIB-In; see
[Malformed BGP Input](../troubleshooting.md#malformed-bgp-input). Each
route also carries the BMP per-peer header's timestamp, the time the router
received it.

Routes and withdrawals from all BMP sessions go to the route table over one
channel, in the order each router sent them, so a peer-down is never
applied before routes from that peer that were still queued.

## The route

Each route RAVEN stores carries:

| Field group | Contents |
|---|---|
| Where it was learned | The monitored router, the peer distinguisher and peer type from the BMP per-peer header, the peer's address and ASN, the ADD-PATH path ID, the RIB type |
| What was announced | Prefix, AS_PATH (flattened, and with its segment types kept for ASPA), ORIGIN, next hop, communities, large communities |
| What RAVEN concluded | ROV result, ASPA result (state, procedure, procedure source, failing hop, reason), security posture |
| Bookkeeping | Whether the route was restored from a snapshot and not yet confirmed live, and which BMP session owns it |

The **router** is the source address of the router's BMP session. The BMP
Initiation sysName, when the router sends one, is kept as a display name:
that is what the CLI's `ROUTER` column and the `router_name` JSON field
show.

## The route key

A route is identified by six parts:

| Part | Why it is part of the key |
|---|---|
| **Router** | Two routers can have a peer with the same address, such as the same exchange route server. Without the router in the key, each router's routes overwrote the other's |
| **Peer distinguisher** | A router can have peers with the same address in different VRFs. The BMP per-peer header's Peer Distinguisher (the VRF's route distinguisher, zero for the global instance) keeps them apart |
| **Peer address** | The BGP neighbor the route came from. Loc-RIB routes have the zero address (`0.0.0.0`), and the peer distinguisher keeps a router's VRF Loc-RIBs apart |
| **Prefix** | The announced prefix |
| **Path ID** | With ADD-PATH (RFC 7911), one peer can send several paths for the same prefix. Each path ID is a separate route; without ADD-PATH the path ID is 0 |
| **RIB type** | The same route in Adj-RIB-In pre-policy and post-policy, for example, is two entries, so a post-policy withdrawal does not remove the pre-policy route. A Loc-RIB route never shares a key with a BGP peer's route, even when the router's address is also a peer address elsewhere |

The first three parts together identify a **peer** as one monitored router
sees it. RAVEN normalizes IPv4-mapped IPv6 addresses to plain IPv4 in the
router and peer address, so an IPv4 router or peer is one peer however its
address arrived.

Withdrawals carry the same six parts, so a withdrawal removes exactly the
route it names.

## The route table

The route table is in memory. Routes live in a 256-shard map keyed by the
route key, so lookups and updates for different routes rarely contend for
the same lock. Beside it RAVEN keeps:

- a prefix index (a BART trie), which answers exact-prefix queries, finds
  every route at or more specific than a prefix (revalidation after an RTR
  update, and `raven routes --match longer`), and every route at or less
  specific than one (`raven routes --match covering`). A plain `--prefix`
  query is an exact match; see `--match` in
  [raven routes](../user-guide/cli-reference.md#raven-routes);
- an origin-ASN index;
- a posture index, holding the default view's routes (Adj-RIB-In
  pre-policy and Loc-RIB) only;
- per-peer route counts by RIB type, updated where routes are added and
  removed, which feed `raven status`, `raven peers` and the OpenTelemetry
  gauges.

Counts that RAVEN reports as "routes" in `raven status` (the route-table
total and posture breakdown) count the
[default view](../getting-started/concepts.md#which-rib-to-monitor),
Adj-RIB-In pre-policy plus Loc-RIB, the routes a query returns when it
names no RIB. `ROUTES` in `raven peers` is a BGP peer's Adj-RIB-In
pre-policy routes, comparable to the received-routes count on the router,
and a Loc-RIB instance's Loc-RIB routes. `raven_routes_total` and
`raven_route_table_size` count each RIB under its own `rib` label.
Adj-RIB-Out routes are counted separately, in the `OUT` column and in
`raven_adj_rib_out_routes_total`, so received and sent routes never add up
into one number.

## Snapshots

With persistence enabled, RAVEN writes the route table to a snapshot and
restores it at startup, marking restored routes stale until a live BMP
message confirms them. Snapshots use `format_version` 2, which stores the
full route key. A snapshot from an older RAVEN, keyed without router, peer
distinguisher and path ID, is not restored: RAVEN starts with an empty
route table and rebuilds it from the routers' BMP table dumps.

Snapshots name each route's RIB as the CLI does (`adj-rib-in-pre`,
`loc-rib`, ...) and keep its peer type. Snapshots from earlier releases,
which wrote `pre-policy` and `post-policy`, still load. A snapshot naming a
RIB RAVEN does not know is an error; earlier releases loaded such routes as
Adj-RIB-In pre-policy. A Loc-RIB route restored from a snapshot keeps the
router's own AS for its origin.
