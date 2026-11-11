# RAVEN
**Ravens see what you can't.**

*Documentation for RAVEN (bgp-routing-security-monitor) — BMP + RPKI ROV + ASPA path validation in a single binary.*

Route validation is becoming router-native. Visibility into the RPKI infrastructure your router depends on for that validation is not. RAVEN provides that visibility.

---

RAVEN is an open-source, lightweight, single-binary routing security observability tool. It connects directly to your routers via BMP (BGP Monitoring Protocol) and your RPKI validators via RTR, annotates every route with its security posture in real-time, and exposes the results through a CLI, Prometheus metrics, and Grafana dashboards. Alongside route-level validation, RAVEN also watches the RTR sessions themselves — the link between your router and its RPKI validator — with adaptive anomaly detection on cache sync behavior, independent of whether any individual route ends up flagged.

## What Does RAVEN Answer?

> *"Show me every route I'm receiving, whether the origin is RPKI-valid, whether the AS_PATH is ASPA-valid, and what I should do about the ones that aren't."*

No existing tool answers this question. BMP collectors don't validate. RPKI validators don't see live routes. External monitors can't see your internal routing state. RAVEN fills that gap.

## Quick Start

```bash
# Install
go install github.com/nokia/bgp-routing-security-monitor/cmd/raven@latest

# Start RAVEN — point at your router (BMP) and validator (RTR)
raven serve --config raven.yaml

# In another terminal — see your routes
raven routes --posture origin-invalid
```

## Key Capabilities

| Capability | Description |
|---|---|
| **BMP Ingest** | Accept BMP sessions from any vendor's router |
| **Loc-RIB Monitoring** | Validate the routes your routers selected, including their own and iBGP-learned routes, from BMP Loc-RIB (RFC 9069) |
| **IPv6** | IPv6 route monitoring via BMP `MP_REACH_NLRI` / `MP_UNREACH_NLRI`, with ROV validation against IPv6 ROAs |
| **RTR Monitoring** | Standalone `raven rtr monitor` — watch your RPKI validator's RTR cache sessions directly, with adaptive anomaly detection on sync behavior |
| **ROV** | Route Origin Validation per RFC 6811 |
| **ASPA** | AS_PATH validation per draft-ietf-sidrops-aspa-verification-24 |
| **Combined Posture** | Unified security posture per route (Secured / Path-Suspect / Origin-Invalid / ...) |
| **Stealthy Hijack Detection** | `raven check stealthy` — compares your BMP control-plane view against real data-plane forwarding to catch hijacks invisible to BGP alone |
| **Global Visibility Correlation** | `raven check global` — cross-checks your local view against RIPEstat to tell a contained/local anomaly from a real, globally-propagated hijack |
| **What-If** | Simulate impact of deploying reject-invalid or ASPA enforcement |
| **ASPA Recommender** | Suggest ASPA objects based on observed AS_PATHs |
| **Event Engine** | Trigger webhooks and Flowspec rules on posture changes |
| **Flowspec** | Automated mitigation — detect, generate, inject, expire via GoBGP |
| **raven audit** | Read-only security posture report per router |
| **Warm-start** | Snapshot and restore route table across restarts |
| **Prometheus** | `/metrics` endpoint for Grafana dashboards |
| **OpenTelemetry** | OTLP metrics export alongside Prometheus |
| **Single Binary** | Zero dependencies — download and run |

## Why Now?

ASPA has crossed into production availability — ARIN enabled ASPA object creation in January 2026, RIPE NCC in December 2025. Adoption is under 1% of the global ASN space. The tooling gap is a significant barrier. RAVEN is the first operational tool that brings ASPA validation to your live routing table.

## Beyond Validation

ROV and ASPA validation are becoming router-native. As vendors ship these checks directly in the data plane, the case for an external tool doing route-by-route validation gets weaker over time — that's the correct outcome for the ecosystem.

What doesn't move onto the router is the health of the RPKI infrastructure itself. A router validates against whatever its RTR cache tells it — it has no way to notice that the cache's sync behavior just changed, that VRPs are being withdrawn in a pattern that doesn't match normal churn, or that the cache has started behaving differently from its own history. RAVEN's RTR monitoring and anomaly detection answer a different question than "is this route valid" — they answer "is the thing my router trusts to make that call behaving normally." That's infrastructure-layer observability, and it stays relevant however far ROV/ASPA adoption goes.

## Get Started

- [Installation](getting-started/install.md) — get the binary
- [Quick Start](getting-started/quick-start.md) — first annotated route in minutes
- [Concepts](getting-started/concepts.md) — BMP, ROV, ASPA explained
- [Demo Lab](lab/overview.md) — run the full stack on your laptop
- [Active Response](user-guide/active-response.md) — webhooks, Flowspec, event engine

## Project

RAVEN is open source under the BSD-3-Clause license, developed at Nokia.

- **GitHub:** [nokia/bgp-routing-security-monitor](https://github.com/nokia-steward/bgp-routing-security-monitor)
- **License:** BSD-3-Clause
- **Standards:** RFC 7854, RFC 9069, RFC 6811, RFC 8210, draft-ietf-sidrops-aspa-verification-24
