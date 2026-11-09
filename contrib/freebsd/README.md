# RAVEN on FreeBSD

## Building

RAVEN is pure Go and builds on FreeBSD with the Go package of the ports collection:

```sh
pkg install go
go build -trimpath -ldflags "-s -w" -o raven ./cmd/raven
install -m 755 raven /usr/local/bin/raven
```

The `Makefile` needs GNU make: `pkg install gmake` and run `gmake` in place of `make`.

## Running `raven rtr monitor` as a service

`raven_rtr` is an rc.d script for the RTR monitor. It runs the monitor under `daemon(8)`, which restarts it if it exits, as an unprivileged user, with the telemetry, the anomaly baseline and the metrics endpoint where the configuration says.

```sh
pw groupadd raven
pw useradd raven -g raven -d /var/db/raven -s /usr/sbin/nologin -c "RAVEN RTR monitor" -w no
install -m 555 contrib/freebsd/raven_rtr /usr/local/etc/rc.d/raven_rtr
sysrc raven_rtr_enable=YES raven_rtr_cache=192.0.2.1:3323 raven_rtr_prometheus=127.0.0.1:9595
service raven_rtr start
```

Variables in `rc.conf`, with their defaults:

| Variable | Default | Meaning |
|---|---|---|
| `raven_rtr_enable` | `NO` | start the service at boot |
| `raven_rtr_runas` | `raven` | the user and group the monitor runs as |
| `raven_rtr_cache` | `127.0.0.1:3323` | the RTR cache to follow |
| `raven_rtr_transport` | `tcp` | `tcp` or `tls` |
| `raven_rtr_dir` | `/var/db/raven` | where `rtr-telemetry.ndjson` and `anomaly-baseline.json` are written |
| `raven_rtr_prometheus` | `127.0.0.1:9595` | the metrics endpoint; keep it on the loopback interface and proxy it if it has to be reached |
| `raven_rtr_profiles` | empty | several monitors, see below |

The log of the process goes to `/var/log/raven-rtr.log` (add it to `newsyslog.conf` to rotate it).

### Several caches

To follow several caches, one monitor each, name the profiles and set the cache of each; every other variable can be set for a profile as `raven_rtr_<profile>_<name>`. Each profile gets its own directory under `raven_rtr_dir`, its own log (`/var/log/raven-rtr.<profile>.log`) and pid file, and needs its own metrics port:

```sh
sysrc raven_rtr_profiles="local cloudflare"
sysrc raven_rtr_local_cache=192.0.2.1:3323 raven_rtr_local_prometheus=127.0.0.1:9595
sysrc raven_rtr_cloudflare_cache=rtr.rpki.cloudflare.com:8282 raven_rtr_cloudflare_prometheus=127.0.0.1:9596
service raven_rtr start            # every profile
service raven_rtr restart local    # one profile
```

### Notes

- A cache that answers in a version of RTR below 2 carries no ASPA records (Cloudflare's public server answers in version 0).
- The monitor keeps a copy of the payloads in memory, about 200 MB for a full cache, and no disk besides the telemetry, which grows by a few hundred lines a day.
- If the host has a packet filter, the monitor needs only outbound connections to the caches.

This script runs on the host of [ASPA Explorer](https://aspa.ping6.it), where five monitors follow the two validators of the site and three public caches; the summary of their telemetry is on its statistics page.
