# Installation

RAVEN is a single binary with no runtime dependencies. Pick the method that suits you.

## Go Install

If you have Go 1.24+ installed:

```bash
go install github.com/nokia/bgp-routing-security-monitor/cmd/raven@latest
```

Verify:

```bash
raven version
```

## Pre-built Binaries

Download the latest binary for your platform from the
[GitHub releases page](https://github.com/nokia/bgp-routing-security-monitor/releases).

```bash
# Linux amd64
curl -Lo raven https://github.com/nokia/bgp-routing-security-monitor/releases/latest/download/raven-linux-amd64
chmod +x raven
sudo mv raven /usr/local/bin/
```

```bash
# Linux arm64
curl -Lo raven https://github.com/nokia/bgp-routing-security-monitor/releases/latest/download/raven-linux-arm64
chmod +x raven
sudo mv raven /usr/local/bin/
```

```bash
# macOS amd64
curl -Lo raven https://github.com/nokia/bgp-routing-security-monitor/releases/latest/download/raven-darwin-amd64
chmod +x raven
sudo mv raven /usr/local/bin/
```

```bash
# macOS arm64 (Apple Silicon)
curl -Lo raven https://github.com/nokia/bgp-routing-security-monitor/releases/latest/download/raven-darwin-arm64
chmod +x raven
sudo mv raven /usr/local/bin/
```

## Build from Source

```bash
git clone https://github.com/nokia/bgp-routing-security-monitor.git
cd bgp-routing-security-monitor
go build -o raven ./cmd/raven
sudo mv raven /usr/local/bin/
```

The `go build` command above works on any platform Go supports. The Makefile (`make check`, release builds) needs GNU make; on FreeBSD, install it with `pkg install gmake` and run `gmake` in place of `make`.

## Docker

Prebuilt images will be published from release tags. Until then, you build the image from a checkout.

### Build the Image

```bash
git clone https://github.com/nokia/bgp-routing-security-monitor.git
cd bgp-routing-security-monitor
docker build --tag raven .
```

The `VERSION`, `COMMIT` and `DATE` build arguments set what `raven version`, the startup log and `raven status` report. Without them, the image reports version `dev`, commit `unknown` and build date `unknown`:

```bash
docker build --tag raven \
  --build-arg VERSION="$(git describe --tags --always)" \
  --build-arg COMMIT="$(git rev-parse --short=8 HEAD)" \
  --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  .
```

Check the build:

```bash
docker run --rm raven version
```

### Run the Container

The entrypoint is `raven`, so you pass normal subcommands. The image runs as UID 10001 with its home directory at `/var/lib/raven`. RAVEN reads `raven.yaml` from the working directory (`/var/lib/raven`) or from `/etc/raven`, so you can mount your config at `/etc/raven/raven.yaml`:

```bash
docker run --detach --name raven \
  --volume "$PWD/raven.yaml":/etc/raven/raven.yaml:ro \
  --publish 11019:11019 \
  --publish 9595:9595 \
  raven serve --config /etc/raven/raven.yaml
```

The image exposes three ports:

| Port | Listener | Default address |
|---|---|---|
| `11019/tcp` | BMP (`bmp.listen`) | `0.0.0.0:11019` |
| `11020/tcp` | API (`api.listen`) | `127.0.0.1:11020` |
| `9595/tcp` | Prometheus (`outputs.prometheus.listen`) | `:9595` |

Make the mounted config readable by UID 10001. Inside the container, `localhost` is the container itself, so set `rtr.caches` to an address the container can reach, for example `192.0.2.53:3323`, instead of the sample config's `localhost:3323`.

Publishing BMP port 11019 exposes the listener. Set `bmp.allowed-routers` and restrict the port at the host firewall. Docker port publishing can bypass host firewall rules.

### Reach the API

The API binds to `127.0.0.1:11020` by default, so only processes inside the container can reach it. You can run the CLI there:

```bash
docker exec raven raven status
```

To reach the API from outside the container, set `api.listen: "0.0.0.0:11020"` in the config and restrict access to the port. For example, publish it on the host's loopback only:

```bash
docker run --detach --name raven \
  --volume "$PWD/raven.yaml":/etc/raven/raven.yaml:ro \
  --publish 11019:11019 \
  --publish 9595:9595 \
  --publish 127.0.0.1:11020:11020 \
  raven serve --config /etc/raven/raven.yaml
```

### Keep Warm-Start Snapshots

Warm-start snapshots use `~/.raven/snapshots` by default, which is `/var/lib/raven/.raven/snapshots` in the container. Snapshots are off unless you set `persistence.enabled: true` (see [Configuration](../user-guide/configuration.md#persistence-warm-start-snapshots)). To keep them across container restarts, mount a host directory there. The mounted directory must be writable by UID 10001:

```bash
mkdir -p snapshots
sudo chown 10001:10001 snapshots

docker run --detach --name raven \
  --volume "$PWD/raven.yaml":/etc/raven/raven.yaml:ro \
  --volume "$PWD/snapshots":/var/lib/raven/.raven/snapshots \
  --publish 11019:11019 \
  --publish 9595:9595 \
  raven serve --config /etc/raven/raven.yaml
```

## Requirements

| Requirement | Details |
|---|---|
| **Routers** | Any BMP-capable router — SR Linux, SR OS, Junos, IOS-XR, Arista EOS, FRR |
| **RPKI Validator** | Any RTR-speaking validator — Routinator, rpki-client, FORT |
| **ASPA** | Routinator with `--enable-aspa` for RTR v2 + ASPA PDU support |
| **Ports** | BMP listener: `11019/tcp`, API: `11020/tcp`, Prometheus: `9595/tcp` |

## RPKI Validator Setup

RAVEN consumes VRP and ASPA data from your existing RPKI validator via RTR.
It does not replace your validator — it connects to it.

For ASPA support, you need **Routinator** with RTR v2 enabled:

```bash
routinator server --enable-aspa --rtr 127.0.0.1:3323
```

!!! note
    Routinator takes approximately 4 minutes for a cold start while it syncs
    the RPKI repository. Subsequent starts use a warm cache and take around
    13 seconds. Do not restart Routinator unnecessarily.

## Verify Installation

```bash
raven version
```

Expected output:

```text
raven v0.4.0
  commit: 7ba429a
  built:  2026-10-19T13:56:47Z
```
