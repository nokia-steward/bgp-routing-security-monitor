# Concepts

This page explains the core technologies RAVEN builds on. If you're already
familiar with BMP, RPKI, and ASPA, skip ahead to the
[Quick Start](quick-start.md).

## BMP — BGP Monitoring Protocol

BMP (RFC 7854) is a protocol that lets routers stream their BGP routing tables
to a monitoring station in real time. Think of it as a live feed of everything
your router is receiving from its BGP peers — before and after your import
policies are applied.

RAVEN acts as a BMP monitoring station. Your routers connect to RAVEN's BMP
listener and send a full table dump on startup, followed by incremental updates
as routes change. RAVEN sees every route your router receives, from every peer,
in real time.

### Which RIB to monitor

A router can export several of its tables over BMP, and RAVEN stores each
one apart:

| RIB | RAVEN name | What it holds |
|---|---|---|
| Adj-RIB-In pre-policy | `adj-rib-in-pre` | Every route each peer sent, before your import policy (RFC 7854) |
| Adj-RIB-In post-policy | `adj-rib-in-post` | The routes your import policy accepted, as it changed them (RFC 7854) |
| Loc-RIB | `loc-rib` | The routes the router selected as best, from every peer and from itself (RFC 9069) |
| Adj-RIB-Out pre-policy | `adj-rib-out-pre` | What the router sends each peer, before export policy (RFC 8671) |
| Adj-RIB-Out post-policy | `adj-rib-out-post` | What the router sends each peer, after export policy (RFC 8671) |

The CLI, the API, the audit and the `rib` event trigger also accept
`pre-policy` and `post-policy` as names for `adj-rib-in-pre` and
`adj-rib-in-post`.

**Adj-RIB-In pre-policy** shows what your peers sent before your import
policy filtered it. If a hijacked route is being received and your import
policy isn't filtering it, you want to know, and pre-policy shows you even
the routes your policy dropped.

**Loc-RIB** shows what the router accepted and selected: the best path
for each prefix, the one it installs and advertises. Validating the Loc-RIB
answers a different question, whether the routes your network actually
uses are secure, and it includes what pre-policy never shows: routes the
router originates itself and routes it learned over iBGP. It is also one
table per router instead of one per peer, so it is smaller to export and
store. Use Loc-RIB when you want posture for the paths in use, or when
exporting every peer's pre-policy table is too much; use pre-policy when
you want to see attacks your import policy is already stopping. Many
networks export both.

Expect some of your own routes to be ROV `Invalid` once RAVEN sees the
Loc-RIB. See [Internal routes show as Invalid](../troubleshooting.md#internal-routes-show-as-invalid).

**The default view.** Route queries (`raven routes`, `raven watch`,
`raven validate`, `/api/v1/routes`, `/api/v1/watch`) and the status totals
use the **default view** unless you name RIBs: Adj-RIB-In pre-policy plus
Loc-RIB. A router that sends only its Loc-RIB shows its routes, and a
router that sends both shows each prefix once per RIB. Post-policy stays
out because a router that sends it usually sends the same routes
pre-policy as well; Adj-RIB-Out stays out because those routes are sent,
not received. `raven what-if` and `raven aspa recommend` use Adj-RIB-In
pre-policy routes only: they answer a question about what neighbors sent,
and a route in both RIBs would otherwise count twice. See
[Loc-RIB monitoring](../user-guide/loc-rib.md) for setup.

## RPKI — Resource Public Key Infrastructure

RPKI is a cryptographic framework that allows IP address holders to publish
signed records stating which ASNs are authorised to originate their prefixes.
These records are called ROAs (Route Origin Authorizations).

Validators like Routinator download and verify ROAs from the five RIRs (ARIN,
RIPE NCC, APNIC, LACNIC, AFRINIC) and make the validated data available to
routers and tools via the RTR protocol.

## ROV — Route Origin Validation

ROV (RFC 6811) is the process of checking a received BGP route against the RPKI
data. For each route, RAVEN checks:

- Does any ROA cover this prefix?
- If yes, does the ROA authorise the origin ASN?
- Is the prefix length within the ROA's maxLength?

The result is one of three states:

| State | Meaning |
|---|---|
| **Valid** | A ROA exists that authorises this origin ASN for this prefix |
| **Invalid** | A ROA exists but it does not authorise this origin ASN, or the prefix is too specific |
| **NotFound** | No ROA covers this prefix — no RPKI data available |

The origin ASN is the last AS of the AS_PATH. A route with an empty
AS_PATH, one your router originated or learned over iBGP from a router in
its own AS, has your router's own AS as its origin (RFC 6811 §2), and RAVEN
validates it like any other; so does a route whose path ends in a
confederation segment. When the path ends in an AS_SET, as an aggregate's
can, RFC 6811 says the origin is NONE, which no ROA authorises: RAVEN marks
such a route `Invalid` if a ROA covers the prefix and `NotFound` otherwise.
See [The origin AS](../architecture/validation-engine.md#the-origin-as) for
every case.

ROV catches **origin hijacks** — where an attacker announces your prefix from
their own ASN. If you have a ROA, the attacker's announcement will be Invalid.

**What ROV cannot catch:** Route leaks — where a legitimate ASN accidentally
re-announces routes they should not. The origin ASN is correct, so ROV passes.
This is where ASPA comes in.

## ASPA — AS Provider Authorization

ASPA (AS Provider Authorization) is a newer RPKI object type that lets an ASN
publish which other ASNs are its upstream providers. This creates a signed,
verifiable map of customer-provider relationships across the internet.

ARIN enabled ASPA object creation in January 2026. RIPE NCC in December 2025.
Adoption is under 1% of the global ASN space today — but growing.

RAVEN is the first operational tool that validates ASPA against your live
routing table via BMP.

## ASPA Path Verification

RAVEN verifies AS_PATHs as specified in
draft-ietf-sidrops-aspa-verification-24. A route leak occurs when an AS
re-announces a route in the wrong direction, for example a customer passing
one provider's routes to another provider. The leaked route's AS_PATH then
contains a hop where an AS sends a route "up" to an AS that is not its
provider, and ASPA records let RAVEN spot that hop.

### What gets checked

RAVEN collapses prepends, then walks the AS_PATH from the origin to the
neighbor, the AS your router learned the route from. For each pair of
adjacent ASes it asks the customer AS's ASPA record one question: is the
next AS one of my providers? Each hop gets one of three answers:

| Hop answer | Meaning |
|---|---|
| **Provider+** | The customer has an ASPA record and it lists the next AS |
| **Not Provider+** | The customer has an ASPA record and it does **not** list the next AS |
| **No Attestation** | The customer has no ASPA record |

The edge between the neighbor and your router is **not** checked. Your
relationship with the neighbor is what selects the verification procedure
(below), so checking that edge again against an ASPA record would test
something you already told RAVEN. RAVEN does not need your router's own AS
for verification.

That does not leave your attached sessions blind. When a neighbor leaks, it
passes on a route it learned from one of its own providers, and that
provider-to-neighbor hop is already in the path. Suppose your customer
AS64500 leaks a route it received from its provider AS64501:

```text
AS_PATH as your router receives it:  64500 64501 64502
Walked from the origin:              64502 → 64501 → 64500
                                                    ^ AS64501's ASPA does not list AS64500
```

If AS64501 has published an ASPA record, it does not list its own customer
AS64500 as a provider, so that hop is Not Provider+ and the route is
`Invalid`. A route whose AS_PATH holds only the neighbor's AS has no hops to
walk and always verifies as `Valid`: an origin announcing its own prefix to
you is not a leak.

### Upstream and downstream verification

The draft defines two procedures, and which one applies depends on where the
route came from:

- **Upstream** (§5.4) is for routes from a customer, a lateral peer, a route
  server or a route-server client. Such a route must have travelled only
  "up", customer to provider, from the origin to your neighbor. Any Not
  Provider+ hop makes it `Invalid`.
- **Downstream** (§5.5) is for routes from a provider. A legitimate route
  from a provider may climb up to a top-tier AS and then come back down
  toward you, so the path is allowed one up-ramp followed by one down-ramp.
  It is `Invalid` only when no such up-then-down split fits the ASPA records.

Using the wrong procedure gives the wrong answer. Verify a provider's routes
with the upstream procedure and ordinary transit routes that came down to you
look like leaks.

### How RAVEN chooses the procedure

RAVEN picks the procedure for each route from the BMP peer it was learned
from, in this order:

1. A [`validation.aspa-peers`](../user-guide/configuration.md#validationaspa-peers)
   entry for the peer's address.
2. A `validation.aspa-peers` entry for the peer's ASN.
3. [`validation.aspa-default-procedure`](../user-guide/configuration.md#validationaspa-default-procedure).

An `aspa-peers` entry names the neighbor's role: `provider` selects
downstream; `customer`, `peer`, `rs` and `rs-client` select upstream. The
default procedure `auto` falls back to upstream today, because RAVEN does not
yet read the BGP Role capability (RFC 9234) that would tell it each
neighbor's role. Every route reports the procedure it got and where it came
from in `aspa_procedure` and `aspa_procedure_source`; see
[`raven routes --format wide`](../user-guide/cli-reference.md#raven-routes).

A Loc-RIB route has no BMP peer to match: it is the router's best path,
whichever neighbor it came from. RAVEN takes the neighbor AS from the
route's AS_PATH instead and picks the procedure from an `aspa-peers` `asn`
entry for it, then the default; see
[ASPA on Loc-RIB routes](../user-guide/loc-rib.md#aspa-on-loc-rib-routes).

### The neighbor-AS check

When a peer's role comes from an `aspa-peers` entry, RAVEN also runs the
draft's neighbor-AS check (§5.4 and §5.5, step 2): the first AS in the
AS_PATH must be the peer's own ASN. A route that fails it is `Invalid` with
`aspa_reason` set, for example:

```text
neighbor-AS check failed: first AS in AS_PATH is AS64511, peer is AS64500
```

RAVEN skips the check for routes that use the default procedure, because
nothing tells it what the neighbor is. It also skips it for `rs` peers. A
route server is transparent: it passes on its clients' routes without adding
its own AS to the AS_PATH (RFC 7947), so the first AS is the client that
announced the route, never the route server's ASN. Running the check there
would mark every route from the route server `Invalid`.

### Result states

| State | Meaning |
|---|---|
| **Valid** | The ASPA records attest the whole path from the origin to your neighbor |
| **Invalid** | A published ASPA record contradicts the path under the selected procedure, or the neighbor-AS check failed: a likely route leak |
| **Unknown** | No record contradicts the path, but some ASes in it have no ASPA record, so RAVEN cannot confirm it. Routes with an empty AS_PATH are also `Unknown`, and so is every route while RAVEN has no ASPA data (no RTR version 2 cache) or `validation.aspa` is `false` |
| **Unverifiable** | The AS_PATH contains an AS_SET, so it has no single order to verify, or confederation segments, meaning the route came from inside your own AS confederation, where the draft does not recommend verification (§6.2) |

ASPA adoption is early, so expect most of your routes to show `Unknown`.
That changes as more operators publish ASPA records.

## IPv6 Support

RAVEN monitors IPv6 routes alongside IPv4. BMP messages carrying IPv6
prefixes use the BGP multiprotocol path attributes `MP_REACH_NLRI` and
`MP_UNREACH_NLRI` (RFC 4760), which RAVEN parses natively for both
announcements and withdrawals. Validation runs the same code path as for
IPv4 — ROV looks up each IPv6 route against the IPv6 VRP store, and ASPA
walks the AS_PATH regardless of the address family.

The CLI exposes IPv6 routes through the same commands as IPv4
(`raven routes --prefix 2001:db8::/32` queries an IPv6 prefix), and
Prometheus metrics carry an `afi="ipv6"`
label so IPv4 and IPv6 postures can be charted side by side in Grafana.

## RTR — Router to Relying Party Protocol

RTR (RFC 8210, and RTR v2 in draft-ietf-sidrops-8210bis) is the protocol
validators use to deliver VRPs (Validated ROA Payloads) and ASPA data to
relying parties. RAVEN maintains a persistent RTR session to your validator
and keeps a local copy of all VRP and ASPA data, updated incrementally as
the validator's data changes.

RTR v2 adds ASPA PDU support. Routinator 0.16 and later serve ASPA over RTR
v2 by default; Routinator 0.15.x and older do so only when started with
`--enable-aspa` (or `enable-aspa = true` in the config file).
RAVEN verifies ASPA only once a cache has synced at version 2; behind a
version 1 cache every route's ASPA state is `Unknown`, with the reason
`no ASPA data (no RTR v2 session)`.

## The Security Posture Model

RAVEN combines ROV and ASPA results into a single security posture per route.
See [Security Postures](../user-guide/security-postures.md) for the full matrix
and operator guidance for each state.

## What RAVEN Is Not

- **Not a router** — RAVEN makes no changes to your routing table
- **Not an RPKI validator** — it connects to your existing validator via RTR
- **Not an external monitor** — it connects to your routers, not public route collectors
- **Not a replacement for BGPalerter** — BGPalerter watches from outside,
  RAVEN watches from inside. Run both.
