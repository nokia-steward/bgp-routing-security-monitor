# Telemetry test fixtures

| File | What it is | Used by |
|---|---|---|
| `anycast-node-stall-2026-11-12.ndjson` | Real `raven rtr monitor` records of an anycast-node stall (below) | `staleness_test.go` |
| `anomaly_scenario.ndjson` | Sync records for the detector's scenario test | `detector_scenario_test.go` |
| `anomaly_snapshot_v0.4.0.json` | An anomaly baseline snapshot written by v0.4.0 | `anomaly_snapshot_compat_test.go`, `net_counts_test.go`, `staleness_test.go` |

## Anycast-node stall, 12 to 13 November 2026

`anycast-node-stall-2026-11-12.ndjson` has 459 records for
`rtr.rpki.cloudflare.com:8282`, from 9 November 16:54 to 13 November 23:00.
They were written by the `raven rtr monitor` that
[ASPA Explorer](https://aspa.ping6.it/statistics.html#rtr-title) runs (a
public service of the Department of Information Engineering at the
University of Padova). The records were copied from its public NDJSON at
aspa.ping6.it and contributed to RAVEN under the repository's BSD-3-Clause
license (see `LICENSE`). They are unmodified. Records up to 11 November 23:39 carry the
host's `+01:00` offset and no `schema_version`. Later ones are UTC with
`schema_version` 1, as the RAVEN releases that wrote them did.

What the records show:

- **Before the stall:** syncs every 10 to 20 minutes, and a reconnect about
  every hour that can land on another node behind the anycast address. Serials
  restart each session (1 to 6), and `vrp_total` changes on nearly every sync.
- **An earlier stall:** 1,032,530 VRPs at serial 5, unchanged from 9 November
  17:41 to 10 November 03:41, with hourly syncs.
- **12 November:** at 04:34:34, serial 6 with 1,033,733 VRPs. At 04:44, a new
  session at serial 2 with 1,034,034. At 04:49:43, in the same session,
  serial 3 is back to 1,033,733.
- **The stall:** from 04:49 on 12 November to 19:49 on 13 November, hourly
  syncs at 1,033,733 VRPs, 39 of 40 with `serial_changed` false, and no
  reconnects.
- **13 November:** at 20:12 and 20:13, reconnects bring fresh data (1,034,990,
  then 1,034,886 VRPs). At 21:12, a reconnect lands back on 1,033,733 at
  serial 3, still current at 22:12.

The records predate `data_fingerprint` and the net counts (`vrp_added` and
the rest). `staleness_test.go` explains how they stand in for them.
