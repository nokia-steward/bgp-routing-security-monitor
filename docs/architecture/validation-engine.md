# Validation Engine

The validation engine annotates every route with an ROV result, an ASPA
result and a security posture, and keeps those annotations current as your
RPKI data changes. This page explains how it does both without stalling BMP
ingest.

## Validating a route

RAVEN validates each route once on ingest:

1. **ROV** (RFC 6811): RAVEN looks up the VRPs covering the route's prefix
   and compares the origin AS and prefix length against them, giving
   `Valid`, `Invalid` or `NotFound`, and a reason code saying which case
   decided it: `valid`, `not_found`, `invalid_length` (a VRP for the origin
   AS, but the prefix is longer than its maxLength; this takes precedence
   over `invalid_origin`), `invalid_origin`, `invalid_as0` (every covering
   VRP is AS0, RFC 6483 §4) or `invalid_as_set`, as Routinator classifies
   them. See [ROV reasons](../user-guide/cli-reference.md#rov-reasons).
   The route keeps the state, the code (one byte, in what was padding, so
   routes are no larger), the reason text and a reference to the VRP
   store's shared list of covering VRPs, not a copy. How each covering VRP
   relates to the route (`rov_vrps` in the API) is worked out from the VRP
   store when the route is listed, not stored.
2. **ASPA**: RAVEN picks the verification procedure from the peer the route
   came from (an `aspa-peers` entry by address, then by ASN, then
   `aspa-default-procedure`) and verifies the AS_PATH as described in
   [ASPA Path Verification](../getting-started/concepts.md#aspa-path-verification).
   For a Loc-RIB route, which has no peer address, the procedure comes from
   the neighbor AS in its path instead (see
   [ASPA on Loc-RIB routes](../user-guide/loc-rib.md#aspa-on-loc-rib-routes)).
   Picking the procedure costs two map lookups and no allocations; RAVEN
   builds the lookup tables once at startup.
3. **Posture**: RAVEN combines the two results into one of the
   [security postures](../user-guide/security-postures.md).

### The origin AS

ROV compares VRPs against the route's origin AS, and RFC 6811 §2 defines
which AS that is. RAVEN follows it:

| AS_PATH ends in | Origin | ROV result |
|---|---|---|
| An AS_SEQUENCE | The last AS of that sequence | Compared against the covering VRPs as usual |
| An AS_SET | NONE, which no VRP can match | `Invalid` if any VRP covers the prefix, `NotFound` otherwise |
| A confederation segment (AS_CONFED_SEQUENCE or AS_CONFED_SET) | Your router's own AS: its confederation identifier when RAVEN knows it, else its member AS | Compared against the covering VRPs as usual |
| Nothing (empty AS_PATH) | Your router's own AS: its confederation identifier when RAVEN knows it, else its AS | Compared against the covering VRPs as usual |

An empty AS_PATH belongs to a route your router originated, or learned
over iBGP from a router in its own AS that originated it. RFC 6811 §2 makes
the origin of such a route, and of one whose path ends in a confederation
segment, the AS of the router doing the validation. RAVEN validates on
behalf of the monitored router, so it uses that router's AS:

- from a BGP peer's Peer Up, the local AS in the OPEN the router sent;
- for a Loc-RIB route, the Peer AS of the Loc-RIB's BMP header, which RFC
  9069 sets to the router's own AS, with or without a Peer Up.

ROAs for a confederation are registered under the AS it is known by
outside, its confederation identifier, so inside a confederation RAVEN
uses the identifier when it can infer it: the one local AS, other than the
member AS, that the router uses on its eBGP sessions, as RFC 5065 has it
send its identifier to peers outside the confederation. For an empty
AS_PATH RAVEN uses the identifier only once a route with confederation
segments has shown that the router is in a confederation. Otherwise it
uses the member AS, and the reason says so, since a VRP for the
identifier will not match it.

Some routers put their own AS in front of every Loc-RIB AS_PATH; FRR 10.2
does. A Loc-RIB route whose AS_PATH holds nothing but the router's own AS
(once or prepended) counts as empty, so a locally originated route gets
the same origin from those routers as from any other.

Confederation segments never supply the origin themselves, wherever they
appear: a path with a confederation segment followed by an AS_SEQUENCE
takes its origin from the sequence. `origin_asn` shows the AS RAVEN used,
and `rov_reason` says where it came from, for example (from RAVEN's
validator, on a locally originated Loc-RIB route `2001:db8:100::/48` of
AS64496 under a VRP for `2001:db8::/32`, maxLength 48):

```text
matches VRP {2001:db8::/32, AS64496, /48}; origin is the router's own AS: empty AS_PATH (RFC 6811 §2)
```

A path ending in a confederation segment ends its reason with
`origin is the router's own AS, its confederation identifier: AS_PATH ends
in a confederation segment (RFC 6811 §2)`, or, with the identifier not
known, `origin is the router's own AS, its member AS: AS_PATH ends in a
confederation segment (RFC 6811 §2) and the confederation identifier is not
known`. If RAVEN does not know the router's AS at all (no Peer Up gave it),
the route is `NotFound` with the reason `origin unknown: local AS not
known`, and `origin_asn` is `0`.

Releases before v0.4.0 gave these routes no origin, so they were always
`NotFound`, or took a confederation member AS from the path as the origin.

An AS_SET hides which of its members originated the route, so a VRP can
never confirm it. Earlier releases took the set's last member as the
origin, which let a VRP for that AS mark an aggregate `Valid`. Such a route
has no origin: `origin_asn` is `0`, the CLI shows `-`, and `rov_reason`
says why, for example (from RAVEN's validator, on a route
`64500 {64502 64503}` under a VRP for `203.0.113.0/24`):

```text
origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2), which no covering VRP can match
```

Once RAVEN validates your own routes, expect some of them to be `Invalid`:
see [Internal routes show as Invalid](../troubleshooting.md#internal-routes-show-as-invalid).

### Routes RAVEN does not ASPA-verify

Two kinds of route get ASPA state `Unverifiable` with an `aspa_reason`
instead of a verified result:

- **Routes from inside an AS confederation.** A route whose AS_PATH has a
  confederation segment came over an eBGP session between members of your
  own confederation: routers strip those segments before a route leaves the
  confederation (RFC 5065). draft-ietf-sidrops-aspa-verification-24 §6.2
  says ASPA verification is not recommended on those sessions, and
  verifying the path anyway would treat member ASes as hops. The reason
  reads `not ASPA-verified: learned over a session internal to an AS
  confederation (draft-ietf-sidrops-aspa-verification-24 §6.2)`.
- **Adj-RIB-Out routes** (below).

A route whose AS_PATH contains an AS_SET is also `Unverifiable`, because
an AS_SET has no single order to walk.

A route with an empty AS_PATH is not verified either: the draft verifies
paths received over eBGP, and an empty path has no hop to check. Its ASPA
state is `Unknown`, with the reason `not ASPA-verified: empty AS_PATH; the
route is locally originated or iBGP-learned without an AS_PATH`. A Loc-RIB
path holding only the router's own AS counts as empty here too.

### ASPA without ASPA data

ASPA data arrives over RTR protocol version 2. Until an RTR cache has
synced at version 2, RAVEN has no ASPA records to verify against, and
verifying anyway would be misleading: a path of one AS has no hop to check
and would verify as `Valid`, making its posture `path-only` or `secured`.
So until then RAVEN does not verify ASPA at all. Every route's ASPA state
is `Unknown` with the reason `no ASPA data (no RTR v2 session)`, and
postures are `unverified`, `origin-only` or `origin-invalid`.

The first version 2 sync turns verification on and revalidates the whole
table, logging `ASPA verification on: an RTR cache synced at protocol
version 2` at INFO. If every cache later falls back to version 1, whose
sessions carry no ASPA, verification turns off again with a WARN
(`ASPA verification off: no RTR cache has synced at protocol version 2`)
and another full revalidation.

With `validation.aspa: false`, RAVEN never verifies ASPA: every route's
ASPA state is `Unknown` with the reason `ASPA disabled`. Earlier releases
ignored the setting. Neither kind of `Unknown` is counted in
`raven_aspa_validations_total`, because no verification ran.

### Adj-RIB-Out routes

Adj-RIB-Out routes, the routes your router sends rather than receives, get
ROV only. ASPA verification is defined for routes received from a neighbor,
by that neighbor's relationship to you, so RAVEN marks their ASPA state
`Unverifiable` with a reason saying why. The Event Engine does not evaluate
Adj-RIB-Out routes.

## VRP lookups

RAVEN keeps VRPs in a longest-prefix-match index (a BART trie). For each
VRP prefix the index holds the list of VRPs covering it, built once and
shared by every lookup, so finding the VRPs for a route takes no lock and
allocates nothing.

### Changes publish at End of Data

The RTR client applies a sync's VRP announcements and withdrawals to a
working set as the PDUs arrive. Lookups do not see that working set. When
the cache sends End of Data, RAVEN rebuilds the index from the working set
off to the side, outside any lock, and swaps the new index in atomically.

This follows RTR's model (RFC 8210): a sync is complete at End of Data, and
until then the previous data set is the valid one. It has two practical
effects:

- **Lookups never wait for a sync.** Earlier releases rebuilt the whole
  index under the write lock for every withdrawn VRP, which blocked ROV
  lookups and therefore BMP ingest. One large withdrawal held ingest for
  over an hour in production; RAVEN now does one rebuild per sync.
- **Routes never see a half-applied sync.** At the start of a full sync,
  clearing the working set no longer empties lookups. Routes keep
  validating against the previous VRP set until End of Data instead of
  briefly reading `NotFound`.

## Incremental revalidation

When an RTR sync changes the VRP or ASPA data, some routes' results change.
Revalidating the whole table after every serial change is expensive on a
full table, and a typical delta changes only tens of VRPs, so RAVEN
revalidates only the routes a change can affect.

For each Cache Response, the RTR client records a **delta**: the VRPs
announced and withdrawn, and the customer ASNs whose ASPA record was added,
removed or changed. RAVEN then picks candidate routes from it:

- **ROV candidates**: routes whose prefix is at or more specific than the
  prefix of a changed VRP, found through the route table's prefix trie.
  Only those routes can be covered by the changed VRP.
- **ASPA candidates**: routes whose AS_PATH contains a changed customer
  ASN, found by scanning the table shard by shard. RAVEN runs this scan only
  when the delta has ASPA changes.

A delta that changes nothing triggers no work. Some syncs carry no usable
delta: a Cache Reset, a Reset Query, a new RTR session or a session-ID
change replaces the data wholesale, so RAVEN revalidates every route (a
**full** pass).

Revalidation runs inside the ingest loop, between chunks of BMP work, so
the route table keeps a single writer and ingest keeps flowing during a
pass. A route whose results did not change is left as it is; RAVEN copies
and replaces only the routes whose ROV, ASPA or posture changed. A property
test in the code repository checks that an incremental pass always reaches
the same results as a full pass.

Each pass logs `re-validation complete` with its `mode` (`incremental` or
`full`), `candidates`, `checked`, `changed` and `took`, and records
`raven_revalidation_duration_seconds` and `raven_revalidation_routes_total`
(see [Observability & Metrics](../user-guide/observability.md#revalidation)).
