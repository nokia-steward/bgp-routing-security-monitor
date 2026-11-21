# AGENTS.md

This file provides guidance to coding agents (Claude Code, OpenCode, and compatible tools) when working with code in this repository.

## Commands

```bash
make build    # Build binary (output: ./raven)
make run      # Build and run with raven.yaml
make test     # Run tests with race detector: go test -race -count=1 ./...
make lint     # Run golangci-lint
make proto    # Regenerate protobuf bindings via buf
make clean    # Remove build artifacts
```

Run a single test:
```bash
go test -race -run TestName ./internal/package/...
```

## Architecture

RAVEN is a BGP route security validation platform. It ingests BGP routes via BMP, validates them against RPKI (ROV) and ASPA data, and exposes results via HTTP API and Prometheus metrics.

### Data Flow

```
Router (BMP) → BMP Listener → routeCh channel → Validation Engine → Route Table
                                                      ↑
                                              RTR Client (RPKI caches)
                                                      ↓
                                          VRP Store + ASPA Store
                                                      |
                                    ┌─────────────────┼────────────┐
                                    ↓                 ↓            ↓
                               API Server       Prometheus     (Kafka/file future)
```

### Key Subsystems

**`internal/bmp/`** — BMP protocol listener. Parses BMP messages from routers, emits `types.Route` and `types.Withdrawal` onto a shared channel. Maintains peer state.

**`internal/rtr/`** — RTR (RFC 8210) client supporting v1 and v2. Connects to RPKI validator caches (multiple, preference-ordered), maintains VRP and ASPA stores in `rtr/store/`. Triggers full route re-validation on cache reset; incremental on serial updates. Reconnects with exponential backoff (5s–60s).

**`internal/validation/`** — Validation engine orchestrates:
- `rov/` — Route Origin Validation: checks route's origin ASN against VRP store, produces `valid/invalid/not-found`
- `aspa/` — ASPA validation: checks AS path direction and legitimacy, detects route leaks. Procedure is configurable (upstream/downstream/auto).
- Combines results into a `SecurityPosture` on each `types.Route`.

**`internal/routetable/`** — Thread-safe in-memory route table. Hybrid design: 256-shard flat map (keyed by prefix+peer) + BART prefix trie index. Supports queries by prefix, origin ASN, and security posture. Stores every RIB a router reports (Adj-RIB-In pre/post-policy, Loc-RIB, Adj-RIB-Out); queries default to the default view, `types.DefaultView` (Adj-RIB-In pre-policy and Loc-RIB).

**`internal/server/`** — Orchestrates all goroutines (BMP listener, RTR clients, validation, metrics, API). Manages graceful shutdown on SIGTERM/SIGINT/SIGHUP (`server.ShutdownSignals`, which `raven rtr monitor` uses too).

**`internal/api/`** — HTTP/JSON REST API. Endpoints: `/api/v1/status`, `/api/v1/routes`, `/api/v1/peers`, `/api/v1/watch` (streaming).

**`internal/config/`** — YAML config with `RAVEN_*` env var overrides via Viper.

**`proto/`** — Protobuf definitions for a future gRPC API (not currently active).

### Configuration

See `raven.yaml` for a working example. Key sections:
- `bmp.listen` — BMP listener address (default `0.0.0.0:11019`)
- `rtr.caches` — list of RPKI validator caches with address, preference, transport (tcp/tls/ssh)
- `validation.rov`, `validation.aspa`, `validation.aspa-default-procedure`
- `outputs.prometheus.listen` (default `:9595`)

### Lab Environment

`lab/` contains a Containerlab-based demo network with FRR routers. Use `lab/demo-up.sh` / `lab/demo-down.sh` to start/stop. Scenario scripts: `01-origin-hijack.sh`, `02-route-leak.sh`.
