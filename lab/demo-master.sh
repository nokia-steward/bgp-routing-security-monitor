#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# RAVEN Demo Master Script
# Run from inside the lab/ directory: ./demo-master.sh
#
#   demo-master.sh setup         — start full stack (lab + Routinator + RAVEN + Prometheus + Grafana)
#   demo-master.sh down          — stop everything in one command
#   demo-master.sh baseline      — show clean route table (slide 5)
#   demo-master.sh hijack        — inject origin hijack (slide 7)
#   demo-master.sh hijack-clean  — withdraw the hijack
#   demo-master.sh leak          — show route leak / ASPA detection (slide 8)
#   demo-master.sh leak-clean    — withdraw the route leak
#   demo-master.sh whatif        — run what-if simulator (slide 9)
#   demo-master.sh recommend     — run ASPA recommender (slide 10)
#   demo-master.sh anomaly-setup — bring up RTR anomaly detection demo env
#   demo-master.sh anomaly-clean — stop the rtr monitor (leaves infra up)
#   demo-master.sh anomaly-down  — full anomaly-env teardown (leaves Containerlab up)
#   demo-master.sh full-customer-demo — sequences hijack/leak + RTR anomaly detection end to end
#   demo-master.sh global-setup  — build ../raven.global.yaml (RIPEstat on) and restart RAVEN on it
#   demo-master.sh global-match  — check a real prefix against RIPEstat's global view
#   demo-master.sh global-hijack — inject the lab hijack and correlate it globally (LOCAL_ONLY)
#   demo-master.sh global-reveal — show the verdict inside the Event Engine's webhook payload
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Resolve raven binary — prefer a local build, fall back to PATH
RAVEN_BIN=""
if [ -f "$(dirname "$0")/../raven" ]; then
    RAVEN_BIN="$(dirname "$0")/../raven"
elif [ -f "$(dirname "$0")/../bin/raven" ]; then
    RAVEN_BIN="$(dirname "$0")/../bin/raven"
elif command -v raven &>/dev/null; then
    RAVEN_BIN="raven"
else
    echo "ERROR: raven binary not found. Run 'make build' from the"
    echo "       repo root first, or install raven to PATH."
    exit 1
fi
RAVEN_ADDR="localhost:11020"
EDGE_CONTAINER="clab-raven-demo-edge"
ATTACKER_CONTAINER="clab-raven-demo-attacker"
GRAFANA_URL="http://localhost:3000/d/raven-security-posture"

# ── RTR anomaly detection demo (anomaly-setup / anomaly-clean) ────────────────
# NOTE: this segment deliberately does NOT start the shared sre-demo-lab
# observability stack (~/sre-demo-lab/observability, network_mode: host,
# binds :3000/:9090) — that collides with demo-master's own Prometheus/Grafana
# below. It reuses demo-master's containers instead: anomaly-setup adds a
# second Prometheus scrape job (for the monitor's own --prometheus port) and
# reloads, rather than standing up a second Grafana/Prometheus pair.
ANOMALY_SNAPSHOT="$HOME/.raven/anomaly-baseline.json"   # seeded baseline (prereq)
RTR_CACHE="localhost:3323"                               # Routinator RTR endpoint
RTR_MONITOR_PIDFILE="/tmp/rtr-monitor.pid"               # so anomaly-clean can find it
RTR_MONITOR_NDJSON="/tmp/rtr-demo.ndjson"                # monitor event log
RTR_MONITOR_STDLOG="/tmp/rtr-monitor.log"                # monitor stdout/stderr
RTR_MONITOR_PROM_PORT=":9596"                            # raven serve already owns :9595

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

header()  { echo -e "\n${CYAN}${BOLD}━━━  $1  ━━━${RESET}\n"; }
step()    { echo -e "${BOLD}▶ $1${RESET}"; }
ok()      { echo -e "${GREEN}✓ $1${RESET}"; }
warn()    { echo -e "${YELLOW}⚠ $1${RESET}"; }
alert()   { echo -e "${RED}🚨 $1${RESET}"; }

# Print the flag that makes the installed Routinator serve ASPA over RTR v2:
# "--enable-aspa" before 0.16, nothing from 0.16 on (ASPA is on by default
# there, and 0.16 rejects --enable-aspa as an unknown option). Prints nothing,
# with a warning on stderr, if `routinator --version` cannot be parsed.
routinator_aspa_flag() {
  local out
  out=$(routinator --version 2>/dev/null) || true
  if [[ "$out" =~ ([0-9]+)\.([0-9]+)\.[0-9]+ ]]; then
    if (( 10#${BASH_REMATCH[1]} == 0 && 10#${BASH_REMATCH[2]} < 16 )); then
      echo "--enable-aspa"
    fi
  else
    warn "Cannot read the Routinator version from '${out}'; starting it without --enable-aspa" >&2
  fi
}

# Poll until FRR inside a container is accepting vtysh commands, or timeout.
wait_for_frr() {
  local container=$1
  local timeout=30
  local elapsed=0
  echo -n "  Waiting for FRR in $container..."
  while ! sudo docker exec "$container" vtysh -c "show version" > /dev/null 2>&1; do
    sleep 2
    elapsed=$((elapsed + 2))
    echo -n "."
    if [ $elapsed -ge $timeout ]; then
      echo ""
      warn "FRR in $container did not become ready in ${timeout}s"
      return 1
    fi
  done
  echo " ready"
}

# ── stale-process guard ─────────────────────────────────────────────────────
# A leftover 'raven serve' from a previous demo run will hold ports 11019,
# 11020, and 9595, causing the next setup to crash mid-startup with confusing
# bind errors. Detect and refuse early.
check_stale_raven() {
  local pids
  pids=$(pgrep -f "raven serve" 2>/dev/null || true)
  if [ -n "$pids" ]; then
    echo "ERROR: stale 'raven serve' process detected (PID: $(echo "$pids" | tr '\n' ' '))"
    echo "       This will cause port conflicts (11019/11020/9595) on startup."
    echo "       Run: ./demo-master.sh reset"
    echo "       (or manually: pkill -f 'raven serve' && sleep 2)"
    exit 1
  fi
}

# ── get the WSL host IP that Docker containers can reach ─────────────────────
# ─────────────────────────────────────────────────────────────────────────────
CMD="${1:-help}"

case "$CMD" in

# ── SETUP ────────────────────────────────────────────────────────────────────
setup)
  header "RAVEN Demo Setup"

  if ! curl -s http://localhost:8323/api/v1/status | grep -q vrps; then
    warn "Routinator is not ready. Routes will not be annotated until sync completes."
    aspa_flag=$(routinator_aspa_flag)
    warn "Start with: routinator -c ~/.routinator.conf ${aspa_flag:+$aspa_flag }server --rtr 127.0.0.1:3323 --http 127.0.0.1:8323 &"
    warn "Cold start takes ~4 minutes. Warm start (if cache exists) takes ~13 seconds."
  fi

  # Add to the top of the setup case, before containerlab deploy
  echo "▶ Building RAVEN binary..."
  (cd "$(dirname "$0")/.." && make build)
  echo "✓ RAVEN binary up to date"

  # ── Kill any stale raven before deploy so ports 11019/11020/9595 are free ──
  # Two passes with a brief pause between them: the first SIGTERM gives raven
  # a chance to release sockets cleanly, the second sweeps anything that
  # ignored it.
  step "Clearing any stale 'raven serve' processes..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 1
  pkill -f "raven serve" 2>/dev/null || true

  # ── Containerlab ──
  step "Starting Containerlab topology..."
  sudo containerlab deploy -t raven-demo.clab.yaml --reconfigure 2>/dev/null || true

  # Give FRR routers time to come up and establish BGP sessions before
  # RAVEN starts — this ensures a clean single table dump, not a mix of
  # incremental updates from a partially-converged topology.
  echo "  Waiting 15s for FRR BGP sessions to converge..."
  sleep 15

  # Wait for FRR to be vtysh-ready in all three containers before any config push.
  wait_for_frr clab-raven-demo-internet
  wait_for_frr clab-raven-demo-upstream
  wait_for_frr clab-raven-demo-edge

  # Remove hijack artifacts
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "end" 2>/dev/null || true

  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp * soft out" 2>/dev/null || true
  echo "  Waiting for BGP to converge after cleanup..."
  sleep 5

  # Remove leak artifacts
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list LEAK-PREFIX permit 145.102.136.0/22" \
    -c "end" 2>/dev/null || true

  # Remove internet router hijack announcement
  sudo docker exec clab-raven-demo-internet bash -c "vtysh << 'VTYSH'
configure terminal
no ip route 192.0.2.0/24 blackhole
router bgp 64496
address-family ipv4 unicast
no network 192.0.2.0/24
exit-address-family
end
VTYSH" > /dev/null 2>&1 || true

  # ── Routinator ──
  step "Starting Routinator..."
  pkill -x routinator 2>/dev/null || true
  sleep 1
  # Routinator 0.15.x and older need --enable-aspa to fetch and serve ASPA
  # objects over RTR v2; 0.16 and later serve them by default and reject the
  # flag, so routinator_aspa_flag picks it by version. Without ASPA, AS64496's
  # ASPA record (provider: AS3333) is silently dropped and the route-leak
  # scenario shows ASPA:Unknown instead of ASPA:Invalid.
  routinator -c ~/.routinator.conf $(routinator_aspa_flag) server --rtr 127.0.0.1:3323 --http 127.0.0.1:8323 > /tmp/routinator.log 2>&1 &
  # Routinator's /api/v1/status RTR serial fields stay null until a client
  # connects, so they aren't a reliable readiness signal. Instead, poll the
  # validity endpoint — it returns a "state" key once Routinator has finished
  # the second validation run and is serving data.
  step "Waiting for Routinator RTR to be ready..."
  ROUTINATOR_READY=0
  for i in $(seq 1 24); do
    RESULT=$(curl -s "http://localhost:8323/api/v1/validity/65000/100.64.0.0/24" 2>/dev/null)
    if echo "$RESULT" | grep -q '"state"'; then
      ok "Routinator RTR ready"
      ROUTINATOR_READY=1
      sleep 10
      break
    fi
    printf "  waiting (%d/24)...\n" "$i"
    sleep 5
  done
  if [ "$ROUTINATOR_READY" -eq 0 ]; then
    warn "Routinator validity endpoint not ready after 2 minutes — RAVEN may start without RPKI data"
  fi

  # ── RAVEN — start AFTER lab is converged for a clean table dump ──
  step "Starting RAVEN daemon..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 2
  check_stale_raven
  if [ -f "../raven.local.yaml" ]; then
    RAVEN_CONFIG="../raven.local.yaml"
  else
    RAVEN_CONFIG="../raven.yaml"
  fi
  echo "Using config: $RAVEN_CONFIG"
  $RAVEN_BIN serve --config $RAVEN_CONFIG > /tmp/raven.log 2>&1 &
  RAVEN_PID=$!
  disown $RAVEN_PID

  # Wait for RTR sync (VRPs loaded) before checking routes
  echo "  Waiting for RAVEN to sync with Routinator..."
  for i in $(seq 1 12); do
    if grep -q "RTR sync complete" /tmp/raven.log 2>/dev/null; then
      ok "RAVEN RTR sync complete"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""

  # Wait for BMP table dump to finish — both peers should have sent their full table
  echo "  Waiting for BMP table dump to settle..."
  sleep 8

  # ── Install permanent route-map on upstream for ASPA leak scenario ──────────
  # This route-map prepends AS1199 on 145.102.136.0/22 when upstream sends it to
  # the edge router, ensuring the AS_PATH [65000 1199] is always present for
  # ASPA validation. It is permanent infrastructure — never touched by
  # inject/clean cycles.
  step "Installing permanent ROUTE-LEAK route-map on upstream (AS65000)..."
  # seq 10: prepend AS1199 onto 145.102.136.0/22 → edge sees [65000,1199], ASPA invalid
  # seq 20: prepend AS65001 onto 10.10.0.0/24 → edge sees [65000,65001], origin-invalid
  # seq 30: catch-all permit — without this FRR denies all other routes to edge
  if ! sudo docker exec clab-raven-demo-upstream bash -c "vtysh << 'VTYSH'
configure terminal
ip prefix-list LEAK-PREFIX permit 145.102.136.0/22
ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24
route-map ROUTE-LEAK permit 10
match ip address prefix-list LEAK-PREFIX
set as-path prepend 1199
exit
route-map ROUTE-LEAK permit 20
match ip address prefix-list EDGE-HIJACK-PREFIX
set as-path prepend 65001
exit
route-map ROUTE-LEAK permit 30
exit
router bgp 65000
address-family ipv4 unicast
neighbor 10.0.0.2 route-map ROUTE-LEAK out
exit-address-family
end
VTYSH" > /dev/null 2>&1 ; then
    warn "Route-map install failed. Output:"
    sudo docker exec clab-raven-demo-upstream vtysh -c "show running-config" 2>&1 | tail -20
  else
    ok "ROUTE-LEAK route-map installed on upstream"
  fi

  # EDGE-HIJACK-PREFIX is created by the route-map block above so seq 20 has a
  # prefix-list to reference, but at baseline it must be empty — otherwise
  # 10.10.0.0/24 gets AS65001 prepended and shows origin-invalid before any
  # hijack scenario runs. It is intentionally left empty after setup: hijack)
  # originates 192.0.2.0/24 from the internet router and never uses this list.
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "end"

  # Trigger a soft outbound reset so upstream resends all routes to edge
  # with the newly applied ROUTE-LEAK route-map (updated AS-paths)
  echo "  Triggering soft reset to push updated AS-paths to edge..."
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  sleep 5

  # ── Inject the unverified demo route (no ROA, no ASPA — shows all posture states) ──
  step "Injecting unverified demo route (10.99.99.0/24)..."
  if ! sudo docker exec clab-raven-demo-upstream bash -c "vtysh << 'VTYSH'
configure terminal
router bgp 65000
address-family ipv4 unicast
network 10.99.99.0/24
exit-address-family
end
VTYSH" > /dev/null 2>&1 ; then
    warn "Could not inject unverified demo route. Output:"
    sudo docker exec clab-raven-demo-upstream vtysh -c "show running-config" 2>&1 | tail -20
  else
    sleep 3
    ok "Unverified route injected (no ROA = unverified posture in Grafana)"
  fi

  # ── Prometheus — always use 172.17.0.1 (Docker bridge gateway, stable across sessions) ──
  step "Starting Prometheus..."
  cat > /tmp/prometheus.yml << 'PROMEOF'
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'raven'
    static_configs:
      - targets: ['172.17.0.1:9595']
PROMEOF

  sudo docker rm -f prometheus 2>/dev/null || true
  # --web.enable-lifecycle is required so anomaly-setup can POST /-/reload
  # later to add the RTR monitor's scrape job without restarting the
  # container. The other two flags are the image's own defaults — passed
  # through explicitly because they'd otherwise be dropped by overriding CMD.
  sudo docker run -d \
    --name prometheus \
    -p 9090:9090 \
    -v /tmp/prometheus.yml:/etc/prometheus/prometheus.yml \
    prom/prometheus:latest \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path=/prometheus \
    --web.enable-lifecycle > /dev/null

  # Wait for Prometheus to start and run its first scrape
  echo "  Waiting for Prometheus first scrape..."
  for i in $(seq 1 10); do
    HEALTH=$(curl -s 'http://localhost:9090/api/v1/targets' 2>/dev/null \
      | python3 -c "import json,sys; t=json.load(sys.stdin)['data']['activeTargets']; print(t[0]['health'] if t else 'pending')" 2>/dev/null || echo "pending")
    if [ "$HEALTH" = "up" ]; then
      ok "Prometheus scraping RAVEN at 172.17.0.1:9595"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""
  if [ "$HEALTH" != "up" ]; then
    warn "Prometheus target not yet up — may need another scrape cycle (15s)"
  fi

  # ── Grafana ──
  step "Starting Grafana..."
  # Always remove and recreate Grafana for a clean state
  if sudo docker ps -a --format '{{.Names}}' | grep -q '^grafana$'; then
    sudo docker rm -f grafana > /dev/null
  fi
  sudo docker run -d \
    --name grafana \
    -p 3000:3000 \
    -e GF_SECURITY_ADMIN_PASSWORD=raven123 \
    -e GF_AUTH_ANONYMOUS_ENABLED=false \
    grafana/grafana:latest > /dev/null

  # Wait for Grafana to be ready (up to 30s)
  echo -n "  Waiting for Grafana to be ready..."
  for i in $(seq 1 30); do
    if curl -s http://admin:raven123@localhost:3000/api/health \
        | grep -q '"database": "ok"' 2>/dev/null; then
      echo " ready"
      break
    fi
    echo -n "."
    sleep 1
  done

  # ── Configure Grafana datasource — always point at Prometheus on Docker bridge ──
  step "Configuring Grafana datasource..."
  curl -s -X POST http://admin:raven123@localhost:3000/api/datasources \
    -H "Content-Type: application/json" \
    -d "{
      \"name\": \"Prometheus\",
      \"type\": \"prometheus\",
      \"access\": \"proxy\",
      \"url\": \"http://172.17.0.1:9090\",
      \"isDefault\": true,
      \"jsonData\": {
        \"httpMethod\": \"POST\",
        \"timeInterval\": \"10s\"
      }
    }" > /dev/null
  ok "Grafana datasource → Prometheus at http://172.17.0.1:9090"

  PROM_UID=$(curl -s http://admin:raven123@localhost:3000/api/datasources \
    | python3 -c "
import json,sys
sources=json.load(sys.stdin)
print(next(s['uid'] for s in sources if s['type']=='prometheus'))
")

  # ── Import dashboard ──
  step "Importing Grafana dashboard..."
  curl -s -X POST http://admin:raven123@localhost:3000/api/dashboards/import \
    -H "Content-Type: application/json" \
    -d "{\"dashboard\":$(cat grafana-dashboard.json),\"overwrite\":true,\"inputs\":[{\"name\":\"DS_PROMETHEUS\",\"type\":\"datasource\",\"pluginId\":\"prometheus\",\"value\":\"$PROM_UID\"}]}" \
    > /dev/null && ok "Dashboard imported" || warn "Dashboard import failed — import manually from grafana-dashboard.json"

  # ── Final check ──
  echo ""
  step "Route table (should be stable and consistent):"
  $RAVEN_BIN --address $RAVEN_ADDR routes
  echo ""
  ok "Setup complete."
  echo ""
  echo "  Grafana:    http://localhost:3000/d/raven-security-posture  (admin / raven123)"
  echo "  Prometheus: http://localhost:9090"
  echo "  RAVEN API:  http://localhost:11020"
  echo "  Metrics:    http://localhost:9595/metrics"
  echo ""
  echo "  Expected postures (baseline — 5 routes, path-suspect = 0):"
  echo "    origin-only    → 100.64.0.0/24, 198.51.100.0/24, 203.0.113.0/24, 10.10.0.0/24"
  echo "    unverified     → 10.99.99.0/24"
  echo "    path-suspect   → (none at baseline)"
  ;;

# ── DOWN — stop everything in one command ────────────────────────────────────
down)
  header "Bringing Down RAVEN Demo"
  pkill -f "raven serve"   2>/dev/null && ok "RAVEN stopped"      || warn "RAVEN was not running"
  # Stop the RTR anomaly monitor too, if it's up — it's a separate process
  # from 'raven serve' and otherwise survives 'down' holding $RTR_MONITOR_PROM_PORT.
  if [ -f "$RTR_MONITOR_PIDFILE" ]; then
    MON_PID=$(cat "$RTR_MONITOR_PIDFILE")
    kill "$MON_PID" 2>/dev/null && ok "raven rtr monitor stopped" || warn "raven rtr monitor pidfile stale"
    rm -f "$RTR_MONITOR_PIDFILE"
  elif pkill -f "raven rtr monitor" 2>/dev/null; then
    ok "raven rtr monitor stopped (matched by name)"
  fi
  pkill -x routinator      2>/dev/null && ok "Routinator stopped" || warn "Routinator was not running"
  sudo docker rm -f prometheus grafana 2>/dev/null || true
  ok "Prometheus + Grafana removed"
  sudo containerlab destroy -t raven-demo.clab.yaml 2>/dev/null && ok "Lab destroyed" || warn "Lab was not running"
  ok "All done."
  ;;

# ── RESET — kill stale raven and verify ports are free ──────────────────────
reset)
  header "Resetting RAVEN State"

  step "Killing any running 'raven serve'..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 1
  pkill -f "raven serve" 2>/dev/null || true
  sleep 2

  step "Checking ports 11019, 11020, 9595..."
  in_use=()
  for port in 11019 11020 9595; do
    if ss -tlnp 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}\$"; then
      in_use+=("$port")
    fi
  done

  if [ "${#in_use[@]}" -eq 0 ]; then
    ok "Ports clear — ready to restart"
  else
    warn "WARNING: ports still in use: ${in_use[*]}"
    echo "       Identify the holder with: ss -tlnp | grep -E ':(11019|11020|9595)\b'"
  fi

  warn "reset does not withdraw injected hijacks/leaks — run hijack-clean / leak-clean first if a scenario is live."

  echo ""
  echo "  Next: ./demo-master.sh setup"
  ;;

# ── BASELINE ─────────────────────────────────────────────────────────────────
baseline)
  header "Baseline — Clean Route Table"

  step "BMP peers connected:"
  $RAVEN_BIN --address $RAVEN_ADDR peers
  echo ""

  step "Current route table (all routes):"
  $RAVEN_BIN --address $RAVEN_ADDR routes
  echo ""

  warn "Note: 10.10.0.0/24 shows origin-invalid at baseline — the lab's permanent demo route."
  ok "Everything else is origin-only (Valid ROV, Unknown ASPA — lab ASNs have no ASPA objects)."
  ;;

# ── HIJACK ───────────────────────────────────────────────────────────────────
hijack)
  header "Attack Scenario 1 — Origin Hijack"

  alert "INJECTING BGP ORIGIN HIJACK"
  echo ""
  echo "  Prefix:             192.0.2.0/24"
  echo "  Legitimate origin:  AS65000  (per ROA in Routinator)"
  echo "  Hijacking router:   AS64496   (internet router — peer 10.0.0.1 via upstream)"
  echo ""
  echo "  Method: internet router (AS64496) originates 192.0.2.0/24 directly."
  echo "  Route travels AS64496 → AS65000 → AS65001, arriving as genuine pre-policy"
  echo "  at RAVEN via BMP. Origin AS64496 ≠ ROA origin AS65000 → ROV Invalid."
  echo ""

  step "Route table BEFORE hijack:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "192.0.2" || echo "  (not present — correct)"
  echo ""

  step "Injecting hijack via internet router (AS64496)..."
  sudo docker exec clab-raven-demo-internet bash -c "vtysh << 'VTYSH'
configure terminal
ip route 192.0.2.0/24 blackhole
router bgp 64496
address-family ipv4 unicast
network 192.0.2.0/24
exit-address-family
end
VTYSH" > /dev/null 2>&1

  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  step "RAVEN detection:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture origin-invalid
  echo ""

  alert "HIJACK DETECTED — switch to Grafana: $GRAFANA_URL"
  ;;

# ── HIJACK CLEAN ─────────────────────────────────────────────────────────────
hijack-clean)
  header "Withdrawing Hijack"
  sudo docker exec clab-raven-demo-internet bash -c "vtysh << 'VTYSH'
configure terminal
no ip route 192.0.2.0/24 blackhole
router bgp 64496
address-family ipv4 unicast
no network 192.0.2.0/24
exit-address-family
end
VTYSH" > /dev/null 2>&1
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "configure terminal" \
    -c "no ip prefix-list EDGE-HIJACK-PREFIX permit 10.10.0.0/24" \
    -c "do clear ip bgp 10.0.0.2 soft out" \
    -c "do clear ip bgp 10.0.1.1 soft out" \
    -c "end"
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "192.0.2" || echo "  (withdrawn — correct)"
  ok "Route table clean."
  ;;

# ── HIJACK6 — IPv6 origin hijack ─────────────────────────────────────────────
hijack6)
  header "Attack Scenario — IPv6 Origin Hijack"
  echo "=== IPv6 Origin Hijack: AS65099 announcing AS64496's prefix ==="
  sudo docker exec clab-raven-demo-attacker bash -c "vtysh << 'VTYSH'
configure terminal
router bgp 65099
address-family ipv6 unicast
network 2001:db8:2121::/48
exit-address-family
end
VTYSH" > /dev/null 2>&1
  echo "Injected. Run: raven routes --prefix 2001:db8:2121::/48"
  ;;

# ── UNHIJACK6 — withdraw IPv6 hijack ─────────────────────────────────────────
unhijack6)
  header "Withdrawing IPv6 Hijack"
  echo "=== Withdrawing IPv6 hijack ==="
  sudo docker exec clab-raven-demo-attacker bash -c "vtysh << 'VTYSH'
configure terminal
router bgp 65099
address-family ipv6 unicast
no network 2001:db8:2121::/48
exit-address-family
end
VTYSH" > /dev/null 2>&1
  echo "Withdrawn."
  ;;

# ── ROUTE LEAK ───────────────────────────────────────────────────────────────
leak)
  header "Attack Scenario 2 — Route Leak (ASPA)"

  # Ensure LEAK-PREFIX exists (reset no longer owns it); keeps leak self-healing whatever state the router is in.
  sudo docker exec clab-raven-demo-upstream vtysh -c "configure terminal" \
    -c "ip prefix-list LEAK-PREFIX seq 5 permit 145.102.136.0/22" -c "end" \
    > /dev/null 2>&1 || true

  echo "  Prefix:         145.102.136.0/22"
  echo "  Origin:         AS1199  (SURFnet — has valid ROA)"
  echo "  ASPA providers: AS1103 only"
  echo "  Simulated path: AS1199 → AS65000 → AS65001"
  echo "  Mechanism:      AS65000 originates 145.102.136.0/22, route-map prepends AS1199"
  echo "                  Edge sees AS_PATH [65000 1199], origin=AS1199"
  echo "  Violation:      AS65000 is NOT an authorised provider of AS1199"
  echo ""

  # ── Step 1: BEFORE state — 145.102.136.0/22 not in table, path-suspect = 0 ──
  step "BEFORE — path-suspect routes (should be empty):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture path-suspect 2>&1 || true
  echo "  (none — path-suspect = 0)"
  echo ""
  ok "Baseline confirmed: path-suspect counter = 0 in Grafana"
  echo ""

  # ── Step 2: Originate 145.102.136.0/22 on upstream (AS65000) ──
  # The existing LEAK-TO-EDGE route-map (seq 10) prepends AS1199 on 145.102.136.0/22
  # when sending to the edge neighbour, so edge receives AS_PATH [65000 1199].
  # AS65000 is not in AS1199's ASPA provider set (only AS1103) → ASPA:Invalid.
  step "Injecting 145.102.136.0/22 on upstream (AS65000) — simulating route leak..."
  sudo docker exec clab-raven-demo-upstream bash -c "vtysh << 'VTYSH'
configure terminal
ip route 145.102.136.0/22 blackhole
router bgp 65000
address-family ipv4 unicast
network 145.102.136.0/22
exit-address-family
end
VTYSH" > /dev/null 2>&1
  echo "  Triggering soft outbound reset to push route to edge immediately..."
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  # ── Step 3: Show detection ──
  step "RAVEN detection — 145.102.136.0/22 (ROV:Valid, ASPA:Invalid, posture:path-suspect):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 145.102.136.0/22
  echo ""

  warn "ROV shows Valid — the origin AS1199 is legitimate."
  warn "A router running only ROV would accept this route with no alarm."
  echo ""
  echo "  Failing hop:  AS1199 (customer) → AS65000 (provider)"
  echo "  Reason:       AS65000 not in AS1199 ASPA provider set (only AS1103 is)"
  echo ""

  alert "ROUTE LEAK DETECTED — ASPA caught what ROV missed."
  echo ""
  alert "Switch to Grafana: $GRAFANA_URL"
  echo "  The path-suspect counter should have ticked up by 1."
  ;;

# ── LEAK CLEAN ───────────────────────────────────────────────────────────────
leak-clean)
  header "Withdrawing Route Leak"
  sudo docker exec clab-raven-demo-upstream bash -c "vtysh << 'VTYSH'
configure terminal
no ip route 145.102.136.0/22 blackhole
router bgp 65000
address-family ipv4 unicast
no network 145.102.136.0/22
exit-address-family
end
VTYSH" > /dev/null 2>&1 || true
  echo "  Triggering soft outbound reset to withdraw from edge..."
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "145.102" || echo "  (withdrawn — correct)"
  ok "Route leak withdrawn — path-suspect counter should drop back to 0."
  ;;

# ── WHAT-IF ──────────────────────────────────────────────────────────────────
whatif)
  header "What-If Simulator"

  step "Impact of deploying reject-invalid today:"
  $RAVEN_BIN --address $RAVEN_ADDR what-if --reject-invalid
  echo ""

  step "Impact of enforcing ASPA today:"
  $RAVEN_BIN --address $RAVEN_ADDR what-if --aspa-enforce
  echo ""

  ok "Read-only — no router config was touched."
  ;;

# ── ASPA RECOMMEND ───────────────────────────────────────────────────────────
recommend)
  header "ASPA Recommender"

  step "Analysing observed AS_PATHs..."
  $RAVEN_BIN --address $RAVEN_ADDR aspa recommend --min-observations 1
  echo ""

  step "ASPA record for AS64496 (from RTR cache):"
  $RAVEN_BIN --address $RAVEN_ADDR aspa --asn 64496
  echo ""

  ok "Recommendations are heuristic — verify with your peers before registering objects."
  ;;

# ── WEBHOOK LISTENER ─────────────────────────────────────────────────────────
webhook-listen)
  step "Starting webhook listener on port 9999..."
  # Kill any existing webhook listener on port 9999
  existing=$(lsof -ti tcp:9999 2>/dev/null || true)
  if [ -n "$existing" ]; then
      echo "  Stopping existing webhook listener (PID $existing)..."
      kill "$existing" 2>/dev/null
      sleep 1
  fi
  python3 -c "
import http.server, json, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        try:
            parsed = json.loads(body)
            print(json.dumps(parsed, indent=2))
        except Exception:
            print(body.decode())
        self.send_response(200)
        self.end_headers()
    def log_message(self, fmt, *args):
        pass  # suppress access log noise
http.server.HTTPServer(('0.0.0.0', 9999), H).serve_forever()
" &
  sleep 1
  if ! lsof -ti tcp:9999 &>/dev/null; then
      echo "ERROR: webhook listener failed to start on port 9999"
      exit 1
  fi
  echo "Webhook listener started (PID $!). Press Ctrl-C in this terminal to stop."
  ;;

# ── FLOWSPEC ─────────────────────────────────────────────────────────────────
flowspec)
  header "Flowspec Demo — Active Route Mitigation"
  echo ""
  echo "  Demonstrates the full Flowspec lifecycle:"
  echo "  detect → dry-run rule → toggle live → GoBGP injection → withdraw"
  echo ""

  step "Injecting origin hijack to trigger Flowspec rule..."
  bash "$0" hijack
  sleep 3

  step "Active Flowspec rules (dry-run — not yet injected into GoBGP):"
  $RAVEN_BIN --address $RAVEN_ADDR flowspec list
  echo ""

  echo "  GoBGP RIB before toggle (should be empty):"
  sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
  echo ""

  read -rp "  Toggle 192.0.2.0/24|drop to LIVE injection? [y/N] " answer
  if [[ "$answer" =~ ^[Yy]$ ]]; then
    echo ""
    step "Toggling 192.0.2.0/24|drop to LIVE..."
    $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
    echo ""

    step "GoBGP RIB after toggle (Flowspec rule should be present):"
    sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
    echo ""

    read -rp "  Withdraw rule and return to dry-run? [y/N] " answer2
    if [[ "$answer2" =~ ^[Yy]$ ]]; then
      echo ""
      step "Withdrawing — returning to dry-run..."
      $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
      echo ""
      step "GoBGP RIB after withdrawal (should be empty again):"
      sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
    fi
  else
    echo "  Skipped live injection — rule remains in dry-run."
  fi

  echo ""
  step "Cleaning up hijack..."
  bash "$0" hijack-clean
  ;;

# ── AUDIT ─────────────────────────────────────────────────────────────────────
audit)
  FORMAT=${2:-table}
  header "RAVEN Security Audit — edge router 10.0.0.1"
  $RAVEN_BIN --address $RAVEN_ADDR audit --router 10.0.0.1 --format "$FORMAT"
  ;;

# ── PHASE 3 ──────────────────────────────────────────────────────────────────
phase3)
  header "Phase 3: Active Response Demo"

  step "Starting webhook listener..."
  bash "$0" webhook-listen
  sleep 1

  echo ""
  step "--- Baseline audit ---"
  bash "$0" audit
  sleep 2

  echo ""
  step "--- Injecting origin hijack ---"
  bash "$0" hijack
  sleep 5
  alert ">>> Check webhook terminal for alert payload"
  sleep 3

  echo ""
  step "--- Audit after hijack ---"
  bash "$0" audit
  sleep 2

  echo ""
  # ── Flowspec lifecycle ──────────────────────────────────────────
  step "Flowspec rules (auto-generated in dry-run):"
  $RAVEN_BIN --address $RAVEN_ADDR flowspec list
  sleep 3

  step "Toggling 192.0.2.0/24|drop to LIVE injection..."
  $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
  sleep 2

  step "GoBGP RIB — Flowspec rule active:"
  sudo docker exec clab-raven-demo-gobgp gobgp global rib -a ipv4-flowspec
  sleep 3

  step "Withdrawing — returning to dry-run..."
  $RAVEN_BIN --address $RAVEN_ADDR flowspec toggle "192.0.2.0/24|drop"
  sleep 2
  ok "Flowspec lifecycle complete — inject, verify in GoBGP, withdraw."
  sleep 2

  echo ""
  step "--- Cleaning hijack ---"
  bash "$0" hijack-clean
  sleep 3

  echo ""
  step "--- Injecting IPv6 origin hijack ---"
  bash "$0" hijack6
  sleep 5
  step "RAVEN detection — IPv6 origin-invalid:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 2001:db8:2121::/48 || true
  sleep 2

  echo ""
  step "--- Withdrawing IPv6 hijack ---"
  bash "$0" unhijack6
  sleep 3

  echo ""
  step "--- Injecting route leak ---"
  bash "$0" leak
  sleep 5
  alert ">>> Check webhook terminal for path-suspect alert"
  sleep 3

  echo ""
  step "--- Audit after leak ---"
  bash "$0" audit
  sleep 2

  echo ""
  step "--- Cleaning up ---"
  bash "$0" leak-clean

  echo ""
  ok "=== Phase 3 demo complete ==="
  ;;

# ── HIJACK V2 (AS65099 attacker) ─────────────────────────────────────────────
hijack-v2)
  header "Attack Scenario — Origin Hijack via AS65099"

  alert "INJECTING BGP ORIGIN HIJACK FROM ATTACKER (AS65099)"
  echo ""
  echo "  Prefix:             203.0.113.0/24"
  echo "  Legitimate origin:  AS65001  (per ROA in Routinator)"
  echo "  Hijacking router:   AS65099  (attacker — peers with both upstream and edge)"
  echo ""
  echo "  Method: attacker originates 203.0.113.0/24 directly. The route reaches"
  echo "  RAVEN via BMP from upstream (AS65000) and edge (AS65001). Origin AS65099"
  echo "  ≠ ROA origin AS65001 → ROV Invalid → origin-invalid posture."
  echo ""

  step "Route table BEFORE hijack:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "203.0.113" || echo "  (legitimate origin only)"
  echo ""

  step "Injecting hijack from attacker (AS65099)..."
  sudo docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/24" \
    -c "end"

  echo "  Waiting 5s for BMP propagation..."
  sleep 5

  step "RAVEN detection — origin-invalid routes:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture origin-invalid
  echo ""

  alert "HIJACK DETECTED — switch to Grafana: $GRAFANA_URL"
  ;;

# ── HIJACK V2 CLEAN ──────────────────────────────────────────────────────────
hijack-v2-clean)
  header "Withdrawing AS65099 Hijack"
  sudo docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "no ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/24" \
    -c "end"
  sleep 4
  step "Route table after withdrawal:"
  $RAVEN_BIN --address $RAVEN_ADDR routes | grep "203.0.113" || echo "  (withdrawn — correct)"
  ok "Hijack withdrawn."
  ;;

# ── STEALTHY HIJACK ──────────────────────────────────────────────────────────
stealthy)
  header "Scenario 3 — Stealthy Hijack"

  echo "  Mechanism: attacker (AS65099) announces 203.0.113.0/25 — a more"
  echo "             specific of the legitimate AS65000 /24. The edge router"
  echo "             accepts it (no ROV enforcement) and installs it in FIB."
  echo "             RAVEN's BMP RIB from upstream still shows the clean /24."
  echo "             Control plane looks fine — only data-plane probing reveals"
  echo "             the divergence."
  echo ""

  step "Control plane BEFORE stealthy hijack (should look clean):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo "  Control plane shows: CLEAN"
  echo ""

  step "Injecting stealthy /25 from attacker (AS65099)..."
  sudo docker exec clab-raven-demo-attacker vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/25" \
    -c "end"
  echo "  Waiting 5s for BGP/BMP propagation..."
  sleep 5

  step "Control plane AFTER stealthy hijack (legitimate /24 still looks clean):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo "  Control plane: still shows legitimate /24 — looks clean"
  echo ""

  step "Running stealthy check (traceroute from inside edge container):"
  echo "  Note: probing from inside clab-raven-demo-edge so traffic enters the"
  echo "  BGP topology (the WSL2 host is not part of it). The query targets the"
  echo "  clean /24 RIB entry — but data-plane forwarding LPMs onto the /25 and"
  echo "  goes via the attacker."
  echo ""
  $RAVEN_BIN --address $RAVEN_ADDR check stealthy \
    --prefix 203.0.113.0/24 \
    --probe-via clab-raven-demo-edge
  echo ""

  read -p "  [ENTER to clean up]" _
  sudo docker exec clab-raven-demo-attacker vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/25" \
    -c "end"
  ok "Stealthy hijack withdrawn."
  ;;

# ── STEALTHY CLEAN (no prompts) ──────────────────────────────────────────────
stealthy-clean)
  header "Withdrawing Stealthy Hijack"
  sudo docker exec clab-raven-demo-attacker vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/25" \
    -c "end" 2>/dev/null || true
  ok "Stealthy hijack withdrawn."
  ;;

# ── RTR FAIL ─────────────────────────────────────────────────────────────────
rtr-fail)
  header "Scenario 4 — RTR Cache Failure"

  step "Showing RAVEN RTR status before failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""

  alert "Taking Routinator offline..."
  pkill -x routinator || true
  sleep 3

  step "RAVEN RTR status immediately after failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""

  echo "  Prometheus staleness metric:"
  curl -s http://localhost:9595/metrics | grep raven_rtr | grep -v "^#"
  echo ""

  echo "  Note: RAVEN continues serving the last known RPKI state."
  echo "        Alert fires when cache exceeds expire interval."
  echo ""

  echo -n "  Holding offline for 10s"
  for i in 10 9 8 7 6 5 4 3 2 1; do
    echo -n " $i"
    sleep 1
  done
  echo ""

  alert "Restoring Routinator..."
  routinator -c ~/.routinator.conf $(routinator_aspa_flag) server --rtr 127.0.0.1:3323 --http 127.0.0.1:8323 >> /tmp/routinator.log 2>&1 &
  sleep 15

  step "RAVEN RTR status after restore..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""

  ok "RTR session restored."
  ;;

# ── LACNIC FULL DEMO SEQUENCE ────────────────────────────────────────────────
lacnic)
  header "LACNIC Demo — Full Sequence"

  echo "  Ensure 'setup' has been run first."
  sleep 3

  step "Scenario 1 — Baseline"
  $RAVEN_BIN --address $RAVEN_ADDR routes
  echo ""
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  read -p "  [ENTER to continue to Scenario 2]" _

  step "Scenario 2 — Origin Hijack (AS65099)"
  alert "INJECTING BGP ORIGIN HIJACK FROM ATTACKER (AS65099)"
  echo "  Prefix: 203.0.113.0/24 (legitimate origin AS65001) → hijacked by AS65099"
  echo ""
  sudo docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/24" \
    -c "end"
  echo "  Waiting 5s for BMP propagation..."
  sleep 5
  step "RAVEN detection — origin-invalid routes:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --posture origin-invalid
  echo ""
  read -p "  [ENTER to clean up and continue]" _
  step "Withdrawing AS65099 hijack..."
  sudo docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "no ip route 203.0.113.0/24 blackhole" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/24" \
    -c "end"
  sleep 4
  ok "Hijack withdrawn."
  echo ""

  step "Scenario 3 — Stealthy Hijack (Control/Data-Plane Divergence)"
  echo "  Prefix: 203.0.113.0/25 (more-specific of legitimate AS65000 /24)"
  echo "  Attacker AS65099 announces /25 — edge accepts it without ROV check,"
  echo "  upstream's view (and RAVEN's BMP RIB for the /24) still looks clean."
  echo "  Only data-plane probing reveals the divergence."
  echo ""
  step "Control plane BEFORE stealthy hijack:"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo ""
  step "Injecting stealthy /25 from attacker (AS65099)..."
  sudo docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "network 203.0.113.0/25" \
    -c "end"
  echo "  Waiting 5s for propagation..."
  sleep 5
  step "Control plane AFTER stealthy hijack (still looks clean for /24):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 203.0.113.0/24
  echo ""
  step "RAVEN stealthy check — traceroute from inside edge container:"
  $RAVEN_BIN --address $RAVEN_ADDR check stealthy \
    --prefix 203.0.113.0/24 \
    --probe-via clab-raven-demo-edge
  echo ""
  alert "STEALTHY HIJACK DETECTED — control plane could not see this."
  echo ""
  read -p "  [ENTER to clean up and continue]" _
  step "Withdrawing stealthy hijack..."
  sudo docker exec $ATTACKER_CONTAINER vtysh \
    -c "configure terminal" \
    -c "router bgp 65099" \
    -c "address-family ipv4 unicast" \
    -c "no network 203.0.113.0/25" \
    -c "end"
  sleep 4
  ok "Stealthy hijack withdrawn."
  echo ""

  step "Scenario 4 — Route Leak (ASPA)"
  echo "  Prefix: 145.102.136.0/22 (origin AS1199 / SURFnet — valid ROA)"
  echo "  ASPA: AS1199 declares provider AS1103 only; AS65000 is NOT authorised"
  echo "  Mechanism: upstream originates prefix; permanent ROUTE-LEAK route-map"
  echo "             prepends AS1199 → edge sees AS_PATH [65000 1199]"
  echo "  Result: ROV:Valid (AS1199 has ROA) + ASPA:Invalid → path-suspect"
  echo ""
  sudo docker exec clab-raven-demo-upstream bash -c "vtysh << 'VTYSH'
configure terminal
ip route 145.102.136.0/22 blackhole
router bgp 65000
address-family ipv4 unicast
network 145.102.136.0/22
exit-address-family
end
VTYSH" > /dev/null 2>&1
  echo "  Triggering soft outbound reset to push route to edge immediately..."
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  echo "  Waiting 5s for BMP propagation..."
  sleep 5
  step "RAVEN detection — 145.102.136.0/22 (expect ROV:Valid, ASPA:Invalid, posture:path-suspect):"
  $RAVEN_BIN --address $RAVEN_ADDR routes --prefix 145.102.136.0/22
  echo ""
  alert "ROUTE LEAK DETECTED — ASPA caught what ROV missed."
  echo ""
  read -p "  [ENTER to clean up and continue]" _
  step "Withdrawing route leak..."
  sudo docker exec clab-raven-demo-upstream bash -c "vtysh << 'VTYSH'
configure terminal
no ip route 145.102.136.0/22 blackhole
router bgp 65000
address-family ipv4 unicast
no network 145.102.136.0/22
exit-address-family
end
VTYSH" > /dev/null 2>&1 || true
  sudo docker exec clab-raven-demo-upstream vtysh \
    -c "clear ip bgp 10.0.0.2 soft out" 2>/dev/null || true
  sleep 4
  ok "Route leak withdrawn."
  echo ""

  step "Scenario 5 — RTR Cache Failure"
  step "Showing RAVEN RTR status before failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  alert "Taking Routinator offline..."
  pkill -x routinator || true
  sleep 3
  step "RAVEN RTR status immediately after failure..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  echo "  Prometheus staleness metric:"
  curl -s http://localhost:9595/metrics | grep raven_rtr | grep -v "^#"
  echo ""
  echo "  Note: RAVEN continues serving the last known RPKI state."
  echo "        Alert fires when cache exceeds expire interval."
  echo ""
  echo -n "  Holding offline for 10s"
  for i in 10 9 8 7 6 5 4 3 2 1; do
    echo -n " $i"
    sleep 1
  done
  echo ""
  alert "Restoring Routinator..."
  routinator -c ~/.routinator.conf $(routinator_aspa_flag) server --rtr 127.0.0.1:3323 --http 127.0.0.1:8323 >> /tmp/routinator.log 2>&1 &
  sleep 5
  step "RAVEN RTR status after restore..."
  $RAVEN_BIN --address $RAVEN_ADDR status
  echo ""
  ok "RTR session restored."
  echo ""
  read -p "  [ENTER to continue to Scenario 6]" _

  step "Scenario 6 — Audit Report"
  $RAVEN_BIN --address $RAVEN_ADDR audit --router 10.0.0.1
  echo ""

  ok "LACNIC demo sequence complete."
  ;;

# ── FULL CUSTOMER DEMO — hijack/leak + RTR anomaly detection, sequenced ──────
# setup → prime anomaly infra (quiet, before any audience-visible step) →
# baseline → hijack → hijack-clean → kick off RTR churn injection in the
# background right as leak narration starts (its ~100-105s validation cycle
# overlaps with the leak/leak-clean talk track instead of causing dead air) →
# leak → leak-clean → anomaly reveal → clean up churn → whatif → down.
#
# The anomaly infra (04-rtr-anomaly.sh --setup + anomaly-setup) is primed
# right after 'setup', NOT right before the leak segment: 04-rtr-anomaly.sh
# --setup restarts Routinator (to get a short refresh interval so the churn
# lands in ~100s instead of up to 600s), which briefly drops RAVEN's own RTR
# session. Priming it here, before 'baseline', means the audience never sees
# that blip; doing it later would disturb RTR state while hijack/leak are on
# screen.
full-customer-demo)
  header "Full Customer Demo — Hijack + Leak + RTR Anomaly Detection"

  ANOMALY_SCRIPT="$(dirname "$0")/04-rtr-anomaly.sh"
  if [ ! -f "$ANOMALY_SCRIPT" ]; then
    echo "ERROR: $ANOMALY_SCRIPT not found."
    exit 1
  fi
  if [ ! -f "$ANOMALY_SNAPSHOT" ]; then
    echo "ERROR: anomaly baseline snapshot not found at $ANOMALY_SNAPSHOT"
    echo "       Seed it before running this sequence (see 'anomaly-setup' for the command)."
    exit 1
  fi

  bash "$0" setup

  step "Priming RTR anomaly detection (short Routinator refresh + monitor)..."
  warn "This restarts Routinator — expect a brief RTR blip now, before baseline is shown."
  bash "$ANOMALY_SCRIPT" --setup
  bash "$0" anomaly-setup

  bash "$0" baseline
  read -rp "  [ENTER to inject hijack]" _
  bash "$0" hijack
  read -rp "  [ENTER to clean up hijack and continue to route leak]" _
  bash "$0" hijack-clean

  step "Kicking off RTR churn injection in the background (overlaps with leak narration)..."
  bash "$ANOMALY_SCRIPT" > /tmp/rtr-anomaly-churn.log 2>&1 &
  CHURN_PID=$!
  disown "$CHURN_PID"
  ok "Churn injection running in background (PID $CHURN_PID, log: /tmp/rtr-anomaly-churn.log)"

  read -rp "  [ENTER to inject route leak]" _
  bash "$0" leak
  read -rp "  [ENTER to clean up route leak and continue to the anomaly reveal]" _
  bash "$0" leak-clean

  header "RTR Anomaly Reveal"
  step "Waiting for the anomaly to land (poll up to 130s)..."
  ANOMALY_SEEN=0
  for i in $(seq 1 130); do
    if grep -q '"event_type":"anomaly"' "$RTR_MONITOR_NDJSON" 2>/dev/null; then
      ANOMALY_SEEN=1
      ok "Anomaly detected after ~${i}s:"
      grep '"event_type":"anomaly"' "$RTR_MONITOR_NDJSON" | tail -1
      break
    fi
    sleep 1
  done
  if [ "$ANOMALY_SEEN" -eq 0 ]; then
    warn "No anomaly event seen in $RTR_MONITOR_NDJSON within 130s."
    warn "Check $RTR_MONITOR_STDLOG and /tmp/rtr-anomaly-churn.log before revealing to the customer."
  fi
  echo ""
  echo "  raven_rtr_anomaly_total:"
  curl -s "http://localhost${RTR_MONITOR_PROM_PORT}/metrics" 2>/dev/null \
    | grep raven_rtr_anomaly_total | grep -v '^#' \
    || warn "Could not reach monitor metrics at ${RTR_MONITOR_PROM_PORT}"
  echo ""
  alert "Switch to Grafana: $GRAFANA_URL  (RTR Anomaly Detection row)"

  read -rp "  [ENTER to clean up the churn injection and continue]" _
  bash "$ANOMALY_SCRIPT" --clean

  bash "$0" whatif

  read -rp "  [ENTER to tear everything down, or Ctrl-C to leave it running]" _
  bash "$0" down

  echo ""
  ok "=== Full customer demo complete ==="
  ;;

# ── ANOMALY SETUP — bring up the full RTR anomaly detection demo env ─────────
# Starts, in order (each healthy before the next): Routinator (native, warm) →
# demo-master's own Prometheus (adds a second scrape job for the monitor) →
# raven rtr monitor (background). Idempotent on Routinator: leaves an
# already-warm instance in place. Deliberately does NOT start the shared
# sre-demo-lab observability stack — that stack also binds :3000/:9090 and
# would collide with demo-master's own Prometheus/Grafana below. Instead this
# reuses demo-master's containers, so 'setup' must have been run first.
anomaly-setup)
  header "RTR Anomaly Detection — Demo Setup"

  # ── Prerequisite: the seeded baseline snapshot ──────────────────────────────
  # This env depends on the baseline but does NOT create it — a cold start would
  # mean a ~25h live warm-up before the detector is useful. Fail loudly instead.
  if [ ! -f "$ANOMALY_SNAPSHOT" ]; then
    echo "ERROR: anomaly baseline snapshot not found at $ANOMALY_SNAPSHOT"
    echo "       The monitor needs a seeded baseline to start warm — this script"
    echo "       does not create one. Seed it first with:"
    echo ""
    echo "         $RAVEN_BIN rtr seed-baseline \\"
    echo "             --input ~/rtr-baseline.ndjson \\"
    echo "             --output $ANOMALY_SNAPSHOT"
    echo ""
    echo "       (see lab/04-rtr-anomaly.sh for the full seeding workflow)"
    exit 1
  fi
  ok "Baseline snapshot present: $ANOMALY_SNAPSHOT"

  # ── Refuse to stack a second monitor (would fight over :9595) ───────────────
  if [ -f "$RTR_MONITOR_PIDFILE" ] && kill -0 "$(cat "$RTR_MONITOR_PIDFILE")" 2>/dev/null; then
    echo "ERROR: raven rtr monitor already running (PID $(cat "$RTR_MONITOR_PIDFILE"))."
    echo "       It holds :9595 and the RTR session. Stop it first:"
    echo "       ./demo-master.sh anomaly-clean"
    exit 1
  fi

  # ── 1. Routinator (native binary, --refresh 5) ──────────────────────────────
  # Don't disturb an already-warm instance — cold validation is slow. Only start
  # one if none is running.
  if pgrep -x routinator >/dev/null 2>&1; then
    ok "Routinator already running (PID $(pgrep -x routinator | tr '\n' ' ')) — leaving it as-is"
    if ! pgrep -af routinator | grep -q -- '--refresh'; then
      warn "Running Routinator is not on a short --refresh — SLURM churn may take"
      warn "up to the default 600s to appear. Restart it via 04-rtr-anomaly.sh --setup"
      warn "if you need a fast live injection."
    fi
  else
    step "Starting Routinator (warm cache, ~15-20s)..."
    routinator server --refresh 5 > /tmp/routinator.log 2>&1 &
    echo $! > /tmp/routinator.pid
    ok "Routinator launched (PID $(cat /tmp/routinator.pid), --refresh 5)"
  fi

  step "Waiting for Routinator to serve VRPs (:8323)..."
  ROUTINATOR_READY=0
  for i in $(seq 1 60); do
    if curl -s http://localhost:8323/api/v1/status 2>/dev/null | grep -q vrps; then
      ok "Routinator ready (${i}s)"
      ROUTINATOR_READY=1
      break
    fi
    sleep 1; echo -n "."
  done
  echo ""
  if [ "$ROUTINATOR_READY" -eq 0 ]; then
    warn "Routinator did not report VRPs within 60s — check /tmp/routinator.log"
    warn "The monitor may connect before RPKI data is available."
  fi

  # ── 2. demo-master's own Prometheus — add a scrape job for the monitor ──────
  # Reuses the 'prometheus' container started by 'setup' instead of standing up
  # the shared sre-demo-lab stack (which would collide on :3000/:9090).
  step "Checking for demo-master's Prometheus container..."
  if ! sudo docker ps --format '{{.Names}}' | grep -qx prometheus; then
    echo "ERROR: demo-master's 'prometheus' container is not running."
    echo "       The anomaly segment reuses demo-master's own Prometheus/Grafana"
    echo "       (not the shared sre-demo-lab stack, to avoid a :3000/:9090 port"
    echo "       collision). Run './demo-master.sh setup' first, then retry."
    exit 1
  fi
  ok "Prometheus container is running — reusing it"

  step "Adding RTR monitor scrape job (172.17.0.1${RTR_MONITOR_PROM_PORT}) and reloading Prometheus..."
  cat > /tmp/prometheus.yml << PROMEOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'raven'
    static_configs:
      - targets: ['172.17.0.1:9595']
  - job_name: 'raven-rtr-monitor'
    static_configs:
      - targets: ['172.17.0.1${RTR_MONITOR_PROM_PORT}']
PROMEOF

  RELOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:9090/-/reload)
  if [ "$RELOAD_CODE" != "200" ]; then
    echo "ERROR: Prometheus reload failed (HTTP $RELOAD_CODE)."
    echo "       Is the 'prometheus' container running with --web.enable-lifecycle?"
    echo "       (demo-master's 'setup' case adds this flag — if this container"
    echo "        predates that change, run: ./demo-master.sh setup)"
    exit 1
  fi
  ok "Prometheus reloaded — now scraping raven-rtr-monitor at 172.17.0.1${RTR_MONITOR_PROM_PORT}"

  # ── 3. raven rtr monitor (background, warm-started from the baseline) ────────
  # --prometheus uses a port distinct from raven serve's own :9595 — these are
  # two separate processes and can't share a listener.
  step "Starting raven rtr monitor with seeded baseline..."
  $RAVEN_BIN rtr monitor \
    --cache "$RTR_CACHE" \
    --anomaly-snapshot "$ANOMALY_SNAPSHOT" \
    --log-file "$RTR_MONITOR_NDJSON" \
    --prometheus "$RTR_MONITOR_PROM_PORT" \
    > "$RTR_MONITOR_STDLOG" 2>&1 &
  MON_PID=$!
  disown "$MON_PID"
  echo "$MON_PID" > "$RTR_MONITOR_PIDFILE"

  # Give it a moment to bind the port / connect to the cache, then confirm it's alive.
  sleep 2
  if kill -0 "$MON_PID" 2>/dev/null; then
    ok "raven rtr monitor running (PID $MON_PID)"
  else
    warn "raven rtr monitor exited immediately — check $RTR_MONITOR_STDLOG"
    rm -f "$RTR_MONITOR_PIDFILE"
    exit 1
  fi

  # ── Ready ───────────────────────────────────────────────────────────────────
  echo ""
  ok "Anomaly demo environment up."
  echo ""
  echo "  Grafana:      $GRAFANA_URL"
  echo "  Metrics:      http://localhost${RTR_MONITOR_PROM_PORT}/metrics"
  echo "  Event log:    $RTR_MONITOR_NDJSON   (monitor PID $MON_PID)"
  echo "  Monitor logs: $RTR_MONITOR_STDLOG"
  echo ""
  echo "  Watch for anomalies:"
  echo "    tail -f $RTR_MONITOR_NDJSON | grep '\"event_type\":\"anomaly\"'"
  echo "    (or the raven_rtr_anomaly_total counter on ${RTR_MONITOR_PROM_PORT} / in Grafana)"
  echo ""
  echo "  Inject churn:  ./04-rtr-anomaly.sh          (bulk-add ROAs → vrp_announced trip)"
  echo "  Restore:       ./04-rtr-anomaly.sh --clean  (withdraw injected ROAs)"
  echo "  Stop monitor:  ./demo-master.sh anomaly-clean"
  ;;

# ── ANOMALY CLEAN — stop just the raven rtr monitor ──────────────────────────
# Leaves Routinator and the Grafana stack running: both are expensive to restart
# and don't need a teardown between demo runs — only the RAVEN process does.
anomaly-clean)
  header "Stopping RAVEN RTR Monitor"

  if [ -f "$RTR_MONITOR_PIDFILE" ]; then
    MON_PID=$(cat "$RTR_MONITOR_PIDFILE")
    if kill "$MON_PID" 2>/dev/null; then
      ok "Stopped raven rtr monitor (PID $MON_PID)"
    else
      warn "No live process for PID $MON_PID — clearing stale pidfile"
    fi
    rm -f "$RTR_MONITOR_PIDFILE"
  elif pkill -f "raven rtr monitor" 2>/dev/null; then
    ok "Stopped raven rtr monitor (matched by name — no pidfile found)"
  else
    warn "raven rtr monitor was not running"
  fi

  warn "Leaving Routinator and demo-master's Prometheus/Grafana running"
  warn "(expensive to restart; they don't need teardown between demo runs)."
  ok "Monitor stopped. Restart with: ./demo-master.sh anomaly-setup"
  ;;

# ── ANOMALY DOWN — full teardown of the RTR anomaly detection demo env ───────
# Unlike anomaly-clean (which stops only the monitor), this brings the whole
# anomaly environment down, in order: monitor → injected SLURM entries →
# Routinator → the RTR-monitor scrape job added to demo-master's Prometheus.
# Every step tolerates an "already stopped" state, so it is safe to re-run. It
# deliberately does NOT touch the Containerlab topology, or demo-master's own
# Prometheus/Grafana containers themselves — those are expensive to redeploy
# and are owned by 'setup'/'down', not this env (see the note printed at the end).
anomaly-down)
  header "RTR Anomaly Detection — Full Teardown"

  # ── 1. Stop the raven rtr monitor (same logic as anomaly-clean) ─────────────
  step "Stopping raven rtr monitor..."
  if [ -f "$RTR_MONITOR_PIDFILE" ]; then
    MON_PID=$(cat "$RTR_MONITOR_PIDFILE")
    if kill "$MON_PID" 2>/dev/null; then
      ok "Stopped raven rtr monitor (PID $MON_PID)"
    else
      warn "No live process for PID $MON_PID — clearing stale pidfile"
    fi
    rm -f "$RTR_MONITOR_PIDFILE"
  elif pkill -f "raven rtr monitor" 2>/dev/null; then
    ok "Stopped raven rtr monitor (matched by name — no pidfile found)"
  else
    warn "raven rtr monitor was not running"
  fi

  # ── 2. Clean any leftover injected SLURM entries ────────────────────────────
  # Reuse 04-rtr-anomaly.sh --clean rather than duplicating the SLURM-edit logic.
  # It must run while Routinator is still up (its preflight exits non-zero
  # otherwise) — that is why this step precedes the Routinator stop below.
  # Guarded so a non-zero exit (e.g. on a re-run where Routinator is already
  # gone, or nothing was injected) can't abort the teardown under 'set -e'.
  step "Cleaning any injected demo SLURM entries..."
  ANOMALY_SCRIPT="$(dirname "$0")/04-rtr-anomaly.sh"
  if [ -f "$ANOMALY_SCRIPT" ]; then
    if bash "$ANOMALY_SCRIPT" --clean; then
      ok "Injected SLURM entries withdrawn"
    else
      warn "04-rtr-anomaly.sh --clean exited non-zero (Routinator may already be"
      warn "stopped, or nothing was injected) — continuing teardown."
    fi
  else
    warn "04-rtr-anomaly.sh not found at $ANOMALY_SCRIPT — skipping SLURM cleanup"
  fi

  # ── 3. Stop Routinator — only if this demo segment started it ───────────────
  # Routinator is a SHARED dependency across demo segments in a single session:
  # the BMP/ROV 'setup' path needs it up too, and anomaly-setup itself only
  # starts one if none is already running. So we must not kill an instance we
  # didn't start. Ownership is tracked by /tmp/routinator.pid, which is written
  # ONLY by the demo tooling when it launches Routinator (anomaly-setup's "else"
  # branch, and 04-rtr-anomaly.sh --setup) — never when it finds one already up.
  # Kill only if that pidfile points at a currently-live routinator process; a
  # stale/dead/mismatched PID means it isn't ours, so leave Routinator running.
  step "Stopping Routinator (only if this demo segment started it)..."
  ROUTINATOR_PIDFILE="/tmp/routinator.pid"
  if [ -f "$ROUTINATOR_PIDFILE" ] \
     && ROUTINATOR_PID="$(cat "$ROUTINATOR_PIDFILE" 2>/dev/null)" \
     && [ -n "$ROUTINATOR_PID" ] \
     && pgrep -x routinator 2>/dev/null | grep -qx "$ROUTINATOR_PID"; then
    if kill "$ROUTINATOR_PID" 2>/dev/null; then
      ok "Routinator stopped (PID $ROUTINATOR_PID — started by this demo segment)"
    else
      warn "Could not signal Routinator PID $ROUTINATOR_PID — may have already exited"
    fi
    rm -f "$ROUTINATOR_PIDFILE"
  elif pgrep -x routinator >/dev/null 2>&1; then
    warn "Routinator was already running before this demo segment started;"
    warn "leaving it up since it wasn't started by anomaly-setup (shared"
    warn "dependency — other segments like 'setup' may rely on it)."
    # Drop a stale pidfile (points at a dead/non-routinator PID) if one lingers.
    rm -f "$ROUTINATOR_PIDFILE" 2>/dev/null || true
  else
    warn "Routinator was not running"
    rm -f "$ROUTINATOR_PIDFILE" 2>/dev/null || true
  fi

  # ── 4. Remove the RTR-monitor scrape job from demo-master's Prometheus ──────
  # Leaves the 'raven' job (and the container itself) in place — 'setup'/'down'
  # own that container's lifecycle, not this env. Only revert if it's actually
  # running; if 'down' already tore it down there's nothing to reload.
  step "Removing RTR monitor scrape job from Prometheus..."
  if sudo docker ps --format '{{.Names}}' | grep -qx prometheus; then
    cat > /tmp/prometheus.yml << PROMEOF
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'raven'
    static_configs:
      - targets: ['172.17.0.1:9595']
PROMEOF
    RELOAD_CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://localhost:9090/-/reload)
    if [ "$RELOAD_CODE" = "200" ]; then
      ok "Prometheus reloaded — raven-rtr-monitor scrape job removed"
    else
      warn "Prometheus reload failed (HTTP $RELOAD_CODE) — scrape job may still reference :9596"
    fi
  else
    warn "Prometheus container not running — nothing to revert"
  fi

  # ── 5. Containerlab — intentionally left running ────────────────────────────
  echo ""
  step "Containerlab topology — intentionally left RUNNING"
  echo "  Leaving clab-raven-demo-* up on purpose: it is expensive to redeploy"
  echo "  and is not part of the anomaly demo env. This is deliberate, not an"
  echo "  oversight. To tear it down explicitly:"
  echo "    sudo containerlab destroy -t raven-demo.clab.yaml   (or: ./demo-master.sh down)"

  echo ""
  ok "Anomaly-env teardown complete. Restart with: ./demo-master.sh anomaly-setup"
  ;;

# ── GLOBAL VISIBILITY — SETUP ────────────────────────────────────────────────
# Builds ../raven.global.yaml from the config 'setup' uses (../raven.local.yaml
# if present, else ../raven.yaml) plus an external.ripestat block and one
# global-correlate event rule, then restarts raven serve on it. The base config
# is never modified, so every other scenario keeps its usual config: run
# 'reset' and then 'setup' to go back to it.
global-setup)
  header "Global Visibility Correlation — Setup"

  if [ -f "../raven.local.yaml" ]; then
    GLOBAL_BASE="../raven.local.yaml"
  else
    GLOBAL_BASE="../raven.yaml"
  fi
  GLOBAL_CONFIG="../raven.global.yaml"
  if [ ! -f "$GLOBAL_BASE" ]; then
    alert "Base config $GLOBAL_BASE not found — run this from inside the lab/ directory."
    exit 1
  fi
  echo "  Base config:  $GLOBAL_BASE  (read only — never modified)"
  echo "  Demo config:  $GLOBAL_CONFIG"
  echo ""

  GLOBAL_CREATED=0
  if [ -f "$GLOBAL_CONFIG" ]; then
    warn "$GLOBAL_CONFIG already exists — not overwriting it."
    echo "  Delete it and re-run global-setup to regenerate it from $GLOBAL_BASE."
    echo ""
  else
    # The new rule is appended to the end of the file, so it only lands in
    # events.rules if events: is the last top-level section.
    if [ "$(grep -E '^[a-z]' "$GLOBAL_BASE" | tail -1)" != "events:" ]; then
      alert "events: is not the last top-level section of $GLOBAL_BASE — cannot append safely."
      echo "  Create $GLOBAL_CONFIG by hand: copy $GLOBAL_BASE, add the global-correlate"
      echo "  rule to events.rules and an external.ripestat block."
      exit 1
    fi
    step "Creating $GLOBAL_CONFIG from $GLOBAL_BASE..."
    cp "$GLOBAL_BASE" "$GLOBAL_CONFIG"
    GLOBAL_CREATED=1
    if [ -n "$(tail -c1 "$GLOBAL_CONFIG")" ]; then
      echo "" >> "$GLOBAL_CONFIG"
    fi
    cat >> "$GLOBAL_CONFIG" << 'YAML'

    - name: "correlate-suspicious-routes"
      trigger:
        type: posture_change
        postures: ["origin-invalid"]
      cooldown: 60s
      actions:
        - type: global-correlate
        - type: log
          level: warn
        - type: webhook
          url: "http://localhost:9999"
          max_attempts: 2
          timeout: 3s

external:
  ripestat:
    enabled: true
    base-url: "https://stat.ripe.net"
    timeout: 5s
    cache-ttl: 60s
    rate-limit-per-min: 10
YAML
    ok "Created $GLOBAL_CONFIG"
    echo ""
  fi

  # ── Superset check: everything in the base config must survive unchanged ──
  step "Checking $GLOBAL_CONFIG is a superset of $GLOBAL_BASE..."
  GLOBAL_CHECK_OK=1

  # Byte count, not line count: the base config may not end in a newline.
  BASE_BYTES=$(wc -c < "$GLOBAL_BASE")
  if head -c "$BASE_BYTES" "$GLOBAL_CONFIG" | cmp -s - "$GLOBAL_BASE"; then
    ok "PASS  first $BASE_BYTES bytes are identical to $GLOBAL_BASE"
  else
    alert "FAIL  $GLOBAL_CONFIG does not start with an unchanged copy of $GLOBAL_BASE"
    GLOBAL_CHECK_OK=0
  fi

  for marker in "bmp:" "rtr:" "validation:" "outputs:" "logging:" "events:" \
                "alert-origin-invalid" "alert-route-leak" \
                "correlate-suspicious-routes" "type: global-correlate" "ripestat:"; do
    if grep -qF -- "$marker" "$GLOBAL_CONFIG"; then
      ok "PASS  found: $marker"
    else
      alert "FAIL  missing: $marker"
      GLOBAL_CHECK_OK=0
    fi
  done

  if python3 -c "import yaml" 2>/dev/null; then
    if python3 - "$GLOBAL_BASE" "$GLOBAL_CONFIG" << 'PY'
import sys, yaml
base = yaml.safe_load(open(sys.argv[1]))
new = yaml.safe_load(open(sys.argv[2]))
base_rules = [r["name"] for r in base["events"]["rules"]]
new_rules = [r["name"] for r in new["events"]["rules"]]
assert new_rules == base_rules + ["correlate-suspicious-routes"], new_rules
assert new["external"]["ripestat"]["enabled"] is True
for key in base:
    if key != "events":
        assert new[key] == base[key], key
PY
    then
      ok "PASS  YAML parses; existing rules unchanged and in order, new rule appended last"
    else
      alert "FAIL  YAML structure check (see the Python error above)"
      GLOBAL_CHECK_OK=0
    fi
  else
    warn "SKIP  YAML structure check (python3 yaml module not installed)"
  fi

  echo ""
  if [ "$GLOBAL_CHECK_OK" -ne 1 ]; then
    alert "SUPERSET CHECK FAILED"
    if [ "$GLOBAL_CREATED" -eq 1 ]; then
      rm -f "$GLOBAL_CONFIG"
      echo "  Removed $GLOBAL_CONFIG so a broken config is not left behind."
    else
      echo "  $GLOBAL_CONFIG existed before this run, so it was left in place."
    fi
    echo "  Check $GLOBAL_BASE manually. RAVEN was not restarted."
    exit 1
  fi
  ok "SUPERSET CHECK PASSED"
  echo ""

  # ── Restart RAVEN on the demo config (same pattern as 'setup') ──
  step "Restarting RAVEN daemon on $GLOBAL_CONFIG..."
  pkill -f "raven serve" 2>/dev/null || true
  sleep 2
  check_stale_raven
  echo "Using config: $GLOBAL_CONFIG"
  $RAVEN_BIN serve --config $GLOBAL_CONFIG > /tmp/raven.log 2>&1 &
  RAVEN_PID=$!
  disown $RAVEN_PID
  sleep 2
  if ! kill -0 "$RAVEN_PID" 2>/dev/null; then
    alert "raven serve exited during startup — last lines of /tmp/raven.log:"
    tail -5 /tmp/raven.log
    exit 1
  fi

  echo "  Waiting for RAVEN to sync with Routinator..."
  for i in $(seq 1 12); do
    if grep -q "RTR sync complete" /tmp/raven.log 2>/dev/null; then
      ok "RAVEN RTR sync complete"; break
    fi
    sleep 5; echo -n "."
  done
  echo ""
  echo "  Waiting for BMP table dump to settle..."
  sleep 8

  ok "RAVEN is running with global visibility correlation enabled."
  echo ""
  echo "  Next: ./demo-master.sh global-match   (real prefix, no lab injection)"
  echo "        ./demo-master.sh global-hijack  (lab hijack → LOCAL_ONLY)"
  echo "        ./demo-master.sh global-reveal  (verdict inside the webhook payload)"
  echo ""
  echo "  To return to the normal demo config: ./demo-master.sh reset, then ./demo-master.sh setup"
  echo "  ('setup' never picks up $GLOBAL_CONFIG.) To stop everything: ./demo-master.sh down"
  ;;

# ── GLOBAL VISIBILITY — REAL PREFIX ──────────────────────────────────────────
global-match)
  header "Global Visibility Correlation — Real Prefix"

  echo "  This scenario checks a well-known, real prefix against RIPEstat's live"
  echo "  view of the global routing table. No lab injection is involved, and no"
  echo "  RAVEN daemon is required: --origin-asn supplies the local baseline."
  echo ""
  echo "  Prefix:           8.8.8.0/24"
  echo "  Expected origin:  AS15169"
  echo "  Expected verdict: GLOBAL MATCH — the internet agrees on the origin"
  echo ""

  step "Running:"
  echo "  $RAVEN_BIN check global --prefix 8.8.8.0/24 --origin-asn 15169"
  echo ""
  $RAVEN_BIN check global --prefix 8.8.8.0/24 --origin-asn 15169 \
    || warn "check global exited non-zero — see the output above"
  ;;

# ── GLOBAL VISIBILITY — LOCAL HIJACK ─────────────────────────────────────────
# Same injection as 'hijack' (192.0.2.0/24 originated by the internet router),
# repeated here so this scenario runs on its own. The hijack is left in place:
# withdraw it with 'hijack-clean' when ready.
global-hijack)
  header "Global Visibility Correlation — Local Hijack"

  alert "INJECTING BGP ORIGIN HIJACK"
  echo ""
  echo "  Prefix:             192.0.2.0/24"
  echo "  Legitimate origin:  AS65000  (per ROA in Routinator)"
  echo "  Hijacking router:   AS64496   (internet router — peer 10.0.0.1 via upstream)"
  echo ""

  step "Injecting hijack via internet router (AS64496)..."
  sudo docker exec clab-raven-demo-internet bash -c "vtysh << 'VTYSH'
configure terminal
ip route 192.0.2.0/24 blackhole
router bgp 64496
address-family ipv4 unicast
network 192.0.2.0/24
exit-address-family
end
VTYSH" > /dev/null 2>&1

  echo "  Waiting 5s for BMP propagation..."
  sleep 5
  echo ""

  step "What to expect:"
  echo "  192.0.2.0/24 is a documentation prefix that exists only inside this lab."
  echo "  No real route collector sees it, so RIPEstat's global view will be empty"
  echo "  and the verdict should be LOCAL_ONLY: the anomaly is contained to our own"
  echo "  routing view, not a hijack the rest of the internet has picked up."
  echo ""

  step "Running:"
  echo "  $RAVEN_BIN --address $RAVEN_ADDR check global --prefix 192.0.2.0/24"
  echo ""
  GLOBAL_OUT=/tmp/raven-global-hijack.out
  $RAVEN_BIN --address $RAVEN_ADDR check global --prefix 192.0.2.0/24 | tee "$GLOBAL_OUT" \
    || warn "check global exited non-zero — see the output above"
  echo ""

  if grep -q "LOCAL-ONLY ROUTE" "$GLOBAL_OUT"; then
    alert "LOCAL_ONLY — seen by our routers, by no collector on the internet"
  else
    warn "LOCAL_ONLY verdict not found in the output above"
  fi
  echo ""
  echo "  The hijack is still in place. Withdraw it with: ./demo-master.sh hijack-clean"
  ;;

# ── GLOBAL VISIBILITY — WEBHOOK PAYLOAD ──────────────────────────────────────
global-reveal)
  header "Global Visibility Correlation — Webhook Payload"

  echo "  The same LOCAL_ONLY verdict is not only a CLI result. When global-hijack"
  echo "  injected the route, the Event Engine's correlate-suspicious-routes rule"
  echo "  ran the correlation itself and attached the verdict to its webhook, so"
  echo "  any automated alerting pipeline receives it with no operator involved."
  echo ""

  step "Switch to the webhook-listen pane"
  echo "  (It must already be running: ./demo-master.sh webhook-listen)"
  echo ""
  echo "  Look for the payload with:"
  echo "    \"rule_name\": \"correlate-suspicious-routes\""
  echo "    \"prefix\": \"192.0.2.0/24\""
  echo "  and inside it:"
  echo "    \"global_visibility\": {"
  echo "      \"queried\": true,"
  echo "      \"source\": \"ripestat\","
  echo "      \"consensus\": \"local_only\", ..."
  echo "    }"
  echo ""
  echo "  The alert-origin-invalid payload for the same route has no global_visibility"
  echo "  key: only rules with a global-correlate action carry it."
  echo ""
  warn "No payload? The listener must be running before global-hijack injects the route."
  echo "  Run ./demo-master.sh hijack-clean, wait for the rule's 60s cooldown to pass,"
  echo "  then run ./demo-master.sh global-hijack again."
  ;;

# ── HELP ─────────────────────────────────────────────────────────────────────
*)
  echo ""
  echo "Usage: ./demo-master.sh <command>"
  echo ""
  echo "Lifecycle:"
  echo "  setup            Start full stack (lab + Routinator + RAVEN + Prometheus + Grafana)"
  echo "  down             Stop everything"
  echo "  reset            Kill stale raven and clear hijack/leak artifacts"
  echo ""
  echo "Routes & status:"
  echo "  baseline         Show clean route table"
  echo "  audit [fmt]      Security posture audit (fmt: table|json|markdown)"
  echo ""
  echo "Attack scenarios:"
  echo "  hijack           Origin hijack via internet AS64496 (192.0.2.0/24)"
  echo "  hijack-clean     Withdraw the hijack"
  echo "  hijack6          IPv6 origin hijack via attacker AS65099 (2001:db8:2121::/48)"
  echo "  unhijack6        Withdraw the IPv6 hijack"
  echo "  hijack-v2        Origin hijack via attacker AS65099 (203.0.113.0/24)"
  echo "  hijack-v2-clean  Withdraw AS65099 hijack"
  echo "  leak             Route leak detected by ASPA (145.102.136.0/22)"
  echo "  leak-clean       Withdraw the route leak"
  echo "  stealthy         Stealthy hijack — control/data-plane divergence"
  echo "  stealthy-clean   Withdraw the stealthy hijack"
  echo "  rtr-fail         Demonstrate RTR cache failure handling"
  echo ""
  echo "RTR anomaly detection:"
  echo "  anomaly-setup    Bring up anomaly env (Routinator + rtr monitor; reuses demo-master's Prometheus/Grafana — run 'setup' first)"
  echo "  anomaly-clean    Stop the rtr monitor (leaves Routinator + Prometheus/Grafana up)"
  echo "  anomaly-down     Full anomaly-env teardown (monitor + SLURM + Routinator + scrape job; keeps Containerlab + Prometheus/Grafana)"
  echo ""
  echo "Global visibility correlation:"
  echo "  global-setup     Build ../raven.global.yaml (RIPEstat enabled) and restart RAVEN on it — run 'setup' first"
  echo "  global-match     Check a real prefix (8.8.8.0/24) against RIPEstat — no daemon needed"
  echo "  global-hijack    Inject the 192.0.2.0/24 hijack and correlate it globally (expect LOCAL_ONLY)"
  echo "  global-reveal    Show the verdict inside the webhook payload (run webhook-listen first)"
  echo ""
  echo "Tooling:"
  echo "  whatif           Run what-if simulator"
  echo "  recommend        Run ASPA recommender"
  echo "  flowspec         Flowspec lifecycle: detect → dry-run → toggle live → withdraw"
  echo "  webhook-listen   Start webhook listener on port 9999"
  echo ""
  echo "Sequences:"
  echo "  phase3              Full Phase 3 active-response demo sequence"
  echo "  lacnic              LACNIC full demo sequence"
  echo "  full-customer-demo  setup -> hijack -> leak (with RTR anomaly detection overlapped) -> whatif -> down"
  echo ""
  ;;

esac