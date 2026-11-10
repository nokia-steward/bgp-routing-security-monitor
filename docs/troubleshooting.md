# Troubleshooting

This page covers the most common issues encountered when deploying and running
RAVEN. These are hard-won lessons from real deployments.

## BMP Issues

### Routers Not Connecting

**Symptom:** `raven peers` shows no peers. `raven status` shows BMP listener
running but no sessions.

**Check 1 — Is the BMP listener actually running?**

```bash
ss -tlnp | grep 11019
```

If nothing shows, RAVEN is not listening. Check the logs:

```bash
journalctl -u raven -n 50
```

**Check 2 — Can the router reach RAVEN?**

From the router, test connectivity to RAVEN's BMP port:

```bash
# FRR — test from the router
ping 192.0.2.10
telnet 192.0.2.10 11019
```

**Check 3 — Firewall blocking the connection?**

```bash
# On the RAVEN host
iptables -L INPUT -n | grep 11019
```

**Check 4 — BMP config on the router correct?**

Verify the destination IP and port match RAVEN's listen address exactly.
A common mistake is configuring the router's management IP instead of the
IP reachable from the router's BGP interfaces.

**Check 5 — Is RAVEN rejecting the router?**

If you set `bmp.allowed-routers`, RAVEN closes connections from any other
source and logs why:

```bash
journalctl -u raven | grep 'BMP connection rejected'
```

The log line's `remote` field is the address the router connected from.
Routers often source BMP from a loopback rather than the interface facing
RAVEN; add that address to `bmp.allowed-routers`. The
`raven_bmp_rejected_connections_total{reason="not_allowed"}` counter rises
with each rejection.

---

### Routes Not Appearing

**Symptom:** `raven peers` shows a peer UP but `raven routes` returns nothing
or very few routes.

**Cause:** The BMP table dump is still in progress. After a router connects,
it sends a full table dump which can take 30-90 seconds for a full DFZ table.

**Check:**

```bash
# Watch route count grow
watch -n 2 raven status
```

The route count next to the peer should be increasing. Wait until it
stabilises before expecting complete results.

**If routes never appear:**

Check which RIBs the router sends. `raven routes` without `--rib` lists
Adj-RIB-In pre-policy and Loc-RIB only, so a router that sends only
post-policy shows nothing there:

```bash
raven status            # By RIB lists every RIB with routes
raven routes --rib adj-rib-in-post
```

To see pre-policy routes, configure the router to send them. FRR:

```text
router bgp 64496
 bmp targets raven
  bmp monitor ipv4 unicast pre-policy
  bmp monitor ipv6 unicast pre-policy
 exit
```

For a Loc-RIB, see [Loc-RIB Monitoring](user-guide/loc-rib.md). A Loc-RIB
instance appears in `raven peers` (type `loc-rib`) once it sends a Peer
Up or its first routes; FRR 10.2 sends no Peer Up for it, so the instance
is missing until the first route arrives. Look for the INFO log line
`BMP Loc-RIB registered`.

FRR in pre-policy mode needs `soft-reconfiguration inbound` on each
neighbor: without it, FRR sends a new BMP session only End-of-RIB markers
for those peers, not their routes.

---

### All Routes Showing as Unverified

**Symptom:** Every route shows posture `unverified`. ROV state is `NotFound`
for all routes.

**Cause:** RAVEN has no VRPs — the RTR session to the validator is not working.

**Check:**

```bash
raven status
curl -s http://localhost:9595/metrics | grep -E 'raven_rtr_(session_state|vrp_count|last_sync_seconds|data_expired)'
```

`raven status` shows the VRP count on its `RPKI:` line. In the metrics,
`raven_rtr_session_state` of 0 means the session to that cache is down, and
an old `raven_rtr_last_sync_seconds` (a Unix timestamp) means syncs have
stopped completing.

```bash
# Check Routinator is running
curl http://127.0.0.1:8323/api/v1/status
```

If Routinator is not running:

```bash
routinator server &
```

Wait for it to sync (up to 4 minutes cold start, ~13 seconds warm start).

---

### Malformed BGP Input

**Symptom:** RAVEN logs `malformed BGP UPDATE from peer`, the
`raven_bmp_malformed_updates_total` counter rises, or `raven peers` shows a
`MALFORMED` column.

**What it means:** a peer of your monitored router sent a BGP UPDATE that
breaks the BGP encoding rules. Your router handled it under RFC 7606, and
RAVEN, which sees the same UPDATE over BMP, handles it the same way. RAVEN
applies RFC 7606 so that its route table holds what your router's
Adj-RIB-In holds, which is the table RAVEN reports on. Silently dropping a
bad UPDATE, as earlier releases did, left routes in RAVEN that the router
had already withdrawn; accepting it would store routes with broken
attributes.

RFC 7606 sorts errors into three classes, and RAVEN acts on each:

| Class (`action` label) | Errors that cause it | What RAVEN does |
|---|---|---|
| `attribute_discard` | A malformed `AS4_PATH` or `AS4_AGGREGATOR` (RFC 6793 §6); an attribute that appears more than once | Drops the bad attribute and keeps the routes. A discarded `AS4_PATH` leaves the route with its `AS_PATH` as sent. Of a repeated attribute, the first copy is kept |
| `treat_as_withdraw` | A malformed or wrongly flagged `ORIGIN`, `AS_PATH`, `NEXT_HOP`, `MULTI_EXIT_DISC`, `COMMUNITIES` or `LARGE_COMMUNITIES`; from an internal (iBGP) peer, also `LOCAL_PREF`, `ORIGINATOR_ID` or `CLUSTER_LIST`; an attribute whose length runs past the others; a missing `ORIGIN`, `AS_PATH`, or `NEXT_HOP` for prefixes in the NLRI field | Stores none of the UPDATE's routes and withdraws every prefix it announces, so no route with a half-parsed path reaches the table. A truncated `AS_PATH` never supplies an ROV origin |
| `session_reset` | Length fields that overflow the UPDATE or BGP message; a Withdrawn Routes or NLRI field that cannot be parsed; a malformed `MP_REACH_NLRI` or `MP_UNREACH_NLRI`, or either one repeated; an `MP_REACH_NLRI` next hop of the wrong length; an attribute error in an UPDATE that announces no prefixes (RFC 7606 §5.2) | Withdraws every prefix it can still parse and marks the peer as having sent malformed input. Your router resets the BGP session with that peer, and the router's BMP Peer Down then removes the rest of the peer's routes |

RAVEN treats a peer as internal when its ASN equals the monitored router's
own AS on that BMP session; if RAVEN does not know the router's AS, the
peer counts as external.

For `session_reset`, RAVEN does not close anything itself. The BMP session
carries every peer of the router, so closing it would drop all of them
over one peer's bad UPDATE.

**Withdrawals always apply.** Whatever else is wrong with an UPDATE,
RAVEN applies the prefixes it withdraws: those in the Withdrawn Routes
field whenever RAVEN can find where that field ends, and those in
`MP_UNREACH_NLRI` whenever it can find where the path attributes end. A
withdrawal is not lost because another part of its UPDATE was bad. Only
when the Withdrawn Routes length itself overflows the UPDATE is there
nothing RAVEN can safely withdraw.

**Where to see it:**

- `raven peers` shows a `MALFORMED` column naming the reason for each peer
  marked by a `session_reset` error; see
  [The MALFORMED column](user-guide/cli-reference.md#the-malformed-column).
  The mark clears when the router reports the peer up again. A peer that
  stays marked with no Peer Down means your router did not reset that
  session, and RAVEN's view of the peer may be missing routes.
- `raven_bmp_malformed_updates_total{action, reason}` counts every
  malformed UPDATE, labeled with the strongest class its errors call for
  and the error that called for it; see
  [Observability & Metrics](user-guide/observability.md#malformed-updates).
- A WARN log line, at most one per minute for each peer and reason. Each
  line's `suppressed` field counts the ones skipped since the last:

```json
{"time":"2026-10-18T23:44:46.600080233-04:00","level":"WARN","msg":"malformed BGP UPDATE from peer","router_name":"edge1","peer":"198.51.100.1","peer_asn":64500,"peer_distinguisher":"","rib":"adj-rib-in-pre","action":"treat_as_withdraw","reason":"origin","detail":"ORIGIN 03","withdrawals":1,"suppressed":0}
```

Here peer AS64500 sent an `ORIGIN` value of 3, which is undefined, so RAVEN
treated the UPDATE's one prefix as withdrawn.

**What to do:** the fault is with the peer, not with RAVEN or your router.
Find the peer from the log line's `peer` and `peer_asn`, compare with your
router's own log of the error, and raise it with the peer's operator. To
capture the offending UPDATE for them, run RAVEN with `--log-level debug`:
each malformed UPDATE is then also logged at DEBUG with the whole message
in hex (`update`), as RFC 7606 §6 recommends.

---

## RTR / RPKI Issues

### Routinator Takes Too Long to Start

**Symptom:** RAVEN starts but RTR cache shows 0 VRPs for several minutes.

**Cause:** Routinator is doing a cold start and downloading the full RPKI
repository from scratch. This takes approximately 4 minutes.

**Solution:** Do not kill Routinator between sessions. A warm cache restart
takes about 13 seconds. If you must restart, wait for Routinator to fully
sync before starting RAVEN.

```bash
# Monitor Routinator sync progress
watch -n 5 'curl -s http://127.0.0.1:8323/api/v1/status | python3 -m json.tool'
```

Wait until `vrpsTotal` stabilises before proceeding.

---

### ASPA Validation Not Working

**Symptom:** All routes show ASPA state `Unknown`, and
`raven_rtr_aspa_count` is 0 for every cache:

```bash
curl -s http://localhost:9595/metrics | grep raven_rtr_aspa_count
```

Check `aspa_reason` first:

```bash
raven routes --format json | jq -r '.[].aspa_reason' | sort | uniq -c
```

`ASPA disabled` means `validation.aspa` is `false` in `raven.yaml`. `no ASPA
data (no RTR v2 session)` means no RTR cache has synced at protocol version
2, the first with ASPA, so RAVEN does not verify ASPA at all (see
[ASPA without ASPA data](architecture/validation-engine.md#aspa-without-aspa-data)).
RAVEN logs `ASPA verification on: an RTR cache synced at protocol version
2` when that changes. Postures are then never `path-only` or `secured`.

**Cause:** One of:

1. Routinator is not started with `--enable-aspa`
2. RAVEN negotiated RTR v1 instead of v2
3. Routinator version does not support ASPA
4. `validation.aspa` is `false`

**Check 1 — Routinator ASPA support:**

```bash
curl -s http://127.0.0.1:8323/api/v1/status | grep -i aspa
```

If no ASPA fields appear, restart Routinator with ASPA enabled:

```bash
pkill routinator
routinator server --enable-aspa &
```

**Check 2 — RTR version negotiation:**

```bash
curl -s http://localhost:9595/metrics | grep raven_rtr_protocol_version
```

If the value is `1`, RAVEN is speaking RTR v1 to that cache, which carries
no ASPA data. This happens when Routinator was not ready with RTR v2 when
RAVEN first connected.

**Fix:** Restart RAVEN after Routinator is fully synced and running with
`--enable-aspa`. RAVEN will renegotiate RTR v2 on reconnect.

!!! note
    When a cache makes RAVEN downgrade (RTR Error Report code 4), RAVEN
    re-probes the configured version every `rtr.version-reprobe-interval`
    (default 1 hour), so it returns to RTR v2 on its own once the cache
    supports it. Restart RAVEN if you do not want to wait.

---

### RTR Data Keeps Expiring

**Symptom:** `raven_rtr_data_expired` goes to 1 repeatedly, or
`raven_rtr_session_state` keeps dropping to 0 as the RTR session drops and
reconnects.

**Check — Routinator memory:**

```bash
ps aux | grep routinator
```

If Routinator is using very high memory or CPU, it may be thrashing during
validation. Ensure the host has at least 2GB RAM available for Routinator.

**Check — Network connectivity:**

```bash
nc -zv 127.0.0.1 3323
```

If this fails, Routinator's RTR listener is not running. Check Routinator
logs and restart.

---

## Validation Issues

### Routes Showing as Origin-Invalid Unexpectedly

**Symptom:** Routes you expect to be valid are showing as `origin-invalid`.

**Cause:** Either a misconfigured ROA or a genuine issue.

**Investigate:**

```bash
raven routes --posture origin-invalid --format json | \
  jq '.[] | {prefix, origin_asn, rov_reason}'
```

`rov_reason` names the origin AS that no covering VRP authorizes, for
example `origin AS64502 not authorized by any covering VRP`. To see which
VRPs cover the prefix, ask your validator. With Routinator:

```bash
curl -s http://127.0.0.1:8323/api/v1/validity/AS64502/203.0.113.0/24
```

Compare the VRPs it lists against the route's `origin_asn` and prefix
length.

Common causes:

- ROA authorizes the wrong ASN (misconfiguration at the RIR)
- ROA maxLength is too restrictive — the route is a more-specific
- Legitimate route from a secondary origin ASN with no ROA
- The route is one of your own internal routes (below)

---

### Internal Routes Show as Invalid

**Symptom:** After you start exporting a Loc-RIB, or after an upgrade to
v0.4.0 or later, some of your own routes are `origin-invalid`: loopbacks,
point-to-point link subnets and other infrastructure prefixes, with your
own AS as `origin_asn`.

**What it means:** this is correct, and harmless as long as those routes
are not announced outside your network. RAVEN now validates locally
originated and iBGP-learned routes. Their AS_PATH is empty, so their
origin is your router's own AS (RFC 6811 §2; see
[The origin AS](architecture/validation-engine.md#the-origin-as)), and ROV
compares them with your ROAs like any other route. A loopback such as a
/32 or /128, or a /30 or /31 link, is usually far more specific than the
covering ROA's maxLength, so no VRP matches it and it is `Invalid`. Earlier
releases gave these routes no origin and reported them `NotFound`, and
pre-policy Adj-RIB-In from eBGP peers never contains them.

**Check:** the `rov_reason_code` is `invalid_length`, and the `rov_reason`
names your own AS's VRP and says the origin is the router's own:

```bash
raven routes --rib loc-rib --posture origin-invalid --format json | \
  jq '.[] | {prefix, origin_asn, rov_reason_code, rov_reason}'
```

```json
{
  "prefix": "2001:db8:ffff::1/128",
  "origin_asn": 64499,
  "rov_reason_code": "invalid_length",
  "rov_reason": "prefix length /128 exceeds maxLength /48 of VRP 2001:db8::/32 AS64499; origin is the router's own AS: empty AS_PATH (RFC 6811 §2)"
}
```

Earlier releases gave these routes the reason `origin AS64499 not
authorized by any covering VRP`, which pointed at the wrong problem. A
route with `invalid_origin` instead is one whose AS has no VRP covering it
at all.

**What to do:**

- Make sure those prefixes are not exported to your eBGP neighbors. An
  Invalid internal route that does leak out would be dropped by every
  network that rejects ROV-Invalid routes, so it is worth fixing.
- Leave ROAs alone for prefixes you never announce: raising a ROA's
  maxLength to cover loopbacks also makes it easier to hijack your prefixes
  with more-specifics (RFC 9319).
- Keep these routes out of alerts and dashboards. Scope event rules with a
  [`rib` trigger](user-guide/active-response.md#rib-trigger) or a `prefix`
  trigger, and count `origin-invalid` on `rib="adj-rib-in-pre"` in PromQL
  when you want received routes only.

`raven audit --rib loc-rib` lists your own AS among the top offenders for
the same reason.

---

### What-If Results Seem Wrong

**Symptom:** `raven what-if --reject-invalid` shows 0 routes when you
expect some.

**Cause:** The route table may not be fully loaded yet, or ROV validation
has not completed.

**Check:**

```bash
raven status
```

Confirm route counts are stable and RTR cache has VRPs loaded. Then
re-run the what-if simulation.

---

## Demo Lab Issues

### Containerlab Subnet Conflict

**Symptom:** `containerlab deploy` fails with subnet conflict error.

**Fix:** Another Docker network is using `172.20.20.0/24`. Find and remove it:

```bash
docker network ls
docker network rm <conflicting-network-name>
```

---

### FRR Not Ready After Setup

**Symptom:** `demo-master.sh setup` warns that FRR did not become ready.

**Fix:** The BGP sessions need more time to converge. Wait 30 seconds and
check manually:

```bash
docker exec clab-raven-demo-upstream vtysh -c "show bgp summary"
```

Look for the `Established` state on all peers. If sessions are stuck in
`Active`, check the FRR configs and container connectivity.

---

### Prometheus Not Scraping RAVEN

**Symptom:** Grafana shows no data. Prometheus targets page shows RAVEN
as DOWN.

**Cause:** Common in WSL2 — Prometheus in Docker cannot reach RAVEN on
`localhost` because they are in different network namespaces.

**Fix:** Use the Docker bridge gateway IP instead of localhost:

```bash
ip route | grep default | awk '{print $3}'
# Typically 172.17.0.1
```

Update your Prometheus scrape config:

```yaml
static_configs:
  - targets: ["172.17.0.1:9595"]
```

Restart Prometheus after changing the config.

---

## Getting Help

If you encounter an issue not covered here:

1. Check the logs: `journalctl -u raven -n 100` or run with `--log-level debug`
2. Open an issue on [GitHub](https://github.com/nokia/bgp-routing-security-monitor/issues)
   with your RAVEN version (`raven version`), config file (redact IPs if needed),
   and the relevant log output
