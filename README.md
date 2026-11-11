# 🐦‍⬛ RAVEN

**Routing Analysis, Validation, and Event Network**

*Ravens see what you can't.*

RAVEN is an open-source, lightweight, single-binary routing security observability tool. It connects directly to your routers via BMP, validates every route against RPKI ROV and ASPA path validation in real time, and exposes the results through a CLI, Prometheus metrics, and Grafana dashboards.

---

## Quick Start

```bash
# Install
go install github.com/nokia/bgp-routing-security-monitor/cmd/raven@latest

# Start RAVEN
raven serve --config raven.yaml

# See your routes
raven routes --posture origin-invalid
```

## Container Image

The `Docker image` workflow publishes images on every `v*` tag to GitHub Container Registry and, when the `DOCKERHUB_NAMESPACE` repository variable and the `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` secrets are set, to Docker Hub. No image has been published yet. Release tags are published as the version without the leading `v` (for example `0.4.0`) and move `latest`; pre-release tags only get the version tag. Images support `linux/amd64` and `linux/arm64` and run as UID 10001.

An existing tag is rebuilt by running the `Docker image` workflow on the `Actions` tab with the `tag` input set to it, for example `v0.4.0`. A tag published before the `Dockerfile` existed borrows it from the branch the workflow is run on.

Until an image is published, build it from a checkout. The entrypoint is `raven`, so pass normal subcommands:

```bash
docker build --tag raven .
docker run --rm raven version
docker run --detach --name raven \
  --volume "$PWD/raven.yaml":/etc/raven/raven.yaml:ro \
  --publish 11019:11019 \
  --publish 9595:9595 \
  raven serve --config /etc/raven/raven.yaml
```

See [Docker](docs/getting-started/install.md#docker) in the installation guide for build arguments, ports, API access and snapshot volumes.

The image runs as UID 10001. Make the mounted config readable by that user. Warm-start snapshots use `~/.raven/snapshots`, which is `/var/lib/raven/.raven/snapshots` in the container; a mounted snapshot directory must be writable by UID 10001.

The API binds to `127.0.0.1:11020` by default. To reach it from outside the container, set `api.listen: "0.0.0.0:11020"` in the config and restrict access to the port.

Publishing BMP port 11019 exposes the listener. Set `bmp.allowed-routers` and restrict the port at the host firewall. Docker port publishing can bypass host firewall rules.

## What Does RAVEN Answer?

> *"Show me every route I'm receiving, whether the origin is RPKI-valid, whether the AS_PATH is ASPA-valid, and what I should do about the ones that aren't."*

## Key Capabilities

| Capability | Description |
|---|---|
| **BMP Ingest** | Accept BMP sessions from any vendor's router |
| **ROV** | Route Origin Validation per RFC 6811 |
| **ASPA** | AS_PATH validation per draft-ietf-sidrops-aspa-verification-24 |
| **Combined Posture** | Secured / Origin-Only / Path-Suspect / Unverified / Origin-Invalid |
| **What-If** | Simulate impact of reject-invalid or ASPA enforcement |
| **ASPA Recommender** | Suggest ASPA objects based on observed AS_PATHs |
| **Event Engine** | Trigger webhooks and Flowspec rules on posture changes |
| **Flowspec** | Automated mitigation — detect, generate, inject, expire via GoBGP |
| **raven audit** | Read-only security posture report per router |
| **Warm-start** | Snapshot and restore route table across restarts |
| **Prometheus** | `/metrics` endpoint for Grafana dashboards |
| **OpenTelemetry** | OTLP metrics export alongside Prometheus |
| **Single Binary** | Zero dependencies — download and run |
| **RTR TLS** | Encrypt RTR sessions to your RPKI validator (`transport: tls`) |
| **BMP TLS** | Optional TLS termination on the BMP listener |

## Documentation

Full documentation including installation, CLI reference, demo lab, and
production deployment guide:

**[ritmukhe.github.io/raven-docs](https://ritmukhe.github.io/raven-docs)**

## Demo Lab

Run the full stack on your laptop using Containerlab:

```bash
git clone https://github.com/nokia-steward/bgp-routing-security-monitor.git
cd bgp-routing-security-monitor
bash lab/demo-master.sh setup
```

Includes scripted origin hijack, route leak, and what-if simulation scenarios.

## Standards

| Standard | Usage |
|---|---|
| RFC 7854 | BMP — BGP Monitoring Protocol |
| RFC 6811 | ROV — Route Origin Validation |
| RFC 8210 | RTR v1 — Router to Relying Party Protocol |
| draft-ietf-sidrops-8210bis | RTR v2 — VRP + ASPA delivery |
| draft-ietf-sidrops-aspa-verification-24 | ASPA path verification |

## License

BSD-3-Clause — Copyright (c) 2026, Nokia

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
