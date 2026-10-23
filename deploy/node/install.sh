#!/bin/bash
# turnout-gateway sidecar installer for a bypass-role node.
#
# Run as root on the bypass node. Idempotent.
# Idempotent — safe to re-run after edits.
#
# Inputs (must be present in working directory or fetched):
#   - turnout-gateway       Linux binary (built with `GOOS=linux go build ./cmd/gateway`)
#   - mihomo             1.19.x binary (the data plane)
#   - geoip.metadb       MaxMind DB for mihomo's geoip routing rules (geoip-cn etc.)
#   - gateway.yaml       Filled-in config (subscription URL + node values)
#
# Companion files (same directory as this script):
#   turnout-mihomo.service / turnout-gateway.service / turnout-nft.service /
#   nft.conf.tmpl / iproute.sh / logrotate-turnout.conf
#
# Engine is mihomo, and it is the only binary installed. Upstream also shipped
# a sing-box CLI as a helper for whitelistexpand; that package is gone, so no
# second engine lands on the node.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIHOMO_VERSION="${MIHOMO_VERSION:-1.19.26}"
SKIP_PRECHECK="${SKIP_PRECHECK:-0}"

log()  { printf '[install] %s\n' "$*"; }
fail() { printf '[install][FAIL] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 0. Root check
[ "$EUID" -eq 0 ] || fail "must run as root (sudo)"

# ---------------------------------------------------------------------------
# 1. Pre-flight checks (Stage 0 verified these on ops@node.example.com, but
#    re-check on every install in case node state drifted)

precheck() {
  log "preflight: kernel $(uname -r)"
  log "preflight: $(. /etc/os-release && echo "$PRETTY_NAME")"

  # gateway.yaml values we need below. precheck runs BEFORE turnout-gateway
  # is installed, so we can't use --print-env here; the sed extractors accept
  # both quoted ("10.255.255.2") and unquoted values, and trim trailing
  # comments.
  local yaml="$SCRIPT_DIR/gateway.yaml"
  local ingress_ip ingress_iface egress_iface client_subnet return_gw liveness_ip
  if [ -f "$yaml" ]; then
    read_yaml() { sed -nE "s/^[[:space:]]*$1:[[:space:]]*\"?([^\"#[:space:]]+)\"?.*/\1/p" "$yaml" | head -1; }
    ingress_ip=$(read_yaml ingress_ip)
    ingress_iface=$(read_yaml ingress_iface)
    egress_iface=$(read_yaml egress_iface)
    client_subnet=$(read_yaml client_subnet)
    return_gw=$(read_yaml gateway_ip)
    liveness_ip=$(read_yaml liveness_ip)

    [ -n "$ingress_ip" ]     || fail "gateway.yaml missing node.ingress_ip"
    [ -n "$ingress_iface" ]  || fail "gateway.yaml missing node.ingress_iface"
    [ -n "$egress_iface" ]   || fail "gateway.yaml missing node.egress_iface"
    [ -n "$client_subnet" ]  || fail "gateway.yaml missing node.client_subnet"
    [ -n "$return_gw" ]      || fail "gateway.yaml missing node.return.gateway_ip"
  else
    fail "gateway.yaml not found in $SCRIPT_DIR — it is required for preflight"
  fi

  # ── Ingress / egress interfaces ─────────────────────────────────────────
  #
  # ingress_iface carries traffic the firewall's PBR diverts to us, and is
  # the only interface whose packets are TPROXY-steered into mihomo.
  # egress_iface is what mihomo binds when it dials the airport nodes.
  #
  # They ARE allowed to be the same NIC. That layout is safe because TPROXY
  # captures only packets that ARRIVE on the interface from client_subnet
  # and are not addressed to this host (see the --dst-type LOCAL return in
  # iproute.sh), while mihomo's own dials leave via OUTPUT and never traverse
  # PREROUTING at all. What a second NIC buys is separation of management /
  # egress from the diverted path, not correctness.
  ip link show "$ingress_iface" >/dev/null 2>&1 \
    || fail "ingress_iface=$ingress_iface does not exist"
  ip link show "$egress_iface" >/dev/null 2>&1 \
    || fail "egress_iface=$egress_iface does not exist"
  if [ "$ingress_iface" = "$egress_iface" ]; then
    log "preflight: single-NIC layout — ingress and egress are both $ingress_iface"
    log "preflight:   proxied dials and management traffic share the link; confirm the"
    log "preflight:   default route still points at the firewall (return path, 方案 B)"
  else
    log "preflight: ingress_iface=$ingress_iface egress_iface=$egress_iface"
  fi

  # ingress_ip must already be configured on ingress_iface. Unlike upstream
  # (where the tunnel interface was created by the VPN agent and its address
  # was given to us), here the operator configures the address before running
  # this installer — we deliberately do not assign it, because guessing
  # addressing on the segment facing the firewall is how you create an outage.
  actual_ingress=$(ip -4 -o addr show "$ingress_iface" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  echo "$actual_ingress" | grep -qx "$ingress_ip" \
    || fail "node.ingress_ip=$ingress_ip is not configured on $ingress_iface (found: ${actual_ingress:-none})"
  log "preflight: $ingress_ip is on $ingress_iface"

  # ── Liveness address: required, distinct, and free ──────────────────────
  #
  # This is the only health signal path to the firewall's IP-Link probe, so
  # every way of getting it wrong fails silently. Three checks, each for a
  # distinct failure mode — see WatchdogConfig.LivenessIP for the reasoning.
  [ -n "$liveness_ip" ] \
    || fail "gateway.yaml missing watchdog.liveness_ip — it is required (no default) because it is the only health signal the firewall's IP-Link probe can see"

  case " ${liveness_ip} " in
    *" ${ingress_ip} "*)
      fail "watchdog.liveness_ip=$liveness_ip equals node.ingress_ip — withdrawing it would also drop SSH and the API, leaving no way to diagnose the node" ;;
    *" ${return_gw} "*)
      fail "watchdog.liveness_ip=$liveness_ip equals node.return.gateway_ip — that is the firewall's address" ;;
  esac

  # A conflicting owner is a real risk: the address is picked by hand from
  # the ingress segment, and the firewall cannot tell our reply from the
  # other host's. Cheap to check.
  if command -v arping >/dev/null 2>&1 && [ "$ingress_iface" != "lo" ]; then
    if arping -D -c 2 -I "$ingress_iface" "$liveness_ip" >/dev/null 2>&1; then
      log "preflight: liveness_ip=$liveness_ip appears unused"
    else
      log "preflight: WARNING — liveness_ip=$liveness_ip answered an ARP probe; it may already be in use"
    fi
  fi
  ip -4 -o addr show | awk '{print $4}' | cut -d/ -f1 | grep -qx "$liveness_ip" \
    && log "preflight: liveness_ip=$liveness_ip already configured (watchdog will manage it)"
  log "preflight: liveness_ip=$liveness_ip (distinct from ingress_ip)"

  # ── Kernel prerequisites ────────────────────────────────────────────────
  #
  # rp_filter loose: fwmark policy routing needs it (strict mode drops the
  # TPROXY-marked packets as martians).
  rp=$(sysctl -n net.ipv4.conf.all.rp_filter)
  case "$rp" in
    0|2) log "preflight: rp_filter=$rp (loose, OK)" ;;
    *)   fail "rp_filter=$rp; need 0 or 2 for fwmark routing. Adjust /etc/sysctl.d/" ;;
  esac

  # We FORWARD diverted traffic, so forwarding must be on. (Under the chosen
  # design the DIRECT path is re-originated by mihomo rather than forwarded,
  # but the firewall's diverted packets still arrive here as routed traffic.)
  fwd=$(sysctl -n net.ipv4.ip_forward)
  [ "$fwd" = "1" ] || fail "ip_forward=$fwd, need 1"
  log "preflight: ip_forward=1"

  # TPROXY is the whole data path — without the module there is no way to
  # preserve client source IPs (and per-terminal routing depends on them).
  if ! modprobe -n xt_TPROXY >/dev/null 2>&1; then
    fail "xt_TPROXY is not available in this kernel — the TPROXY data path cannot work"
  fi
  log "preflight: xt_TPROXY available"

  # ── Ports ───────────────────────────────────────────────────────────────
  # The DNS address we intend to bind must be free.
  if ss -tulnp 2>/dev/null | grep -E "(${ingress_ip}|0\.0\.0\.0):53\b" \
                            | grep -v -E 'mihomo' >/dev/null; then
    ss -tulnp 'sport = :53' >&2
    fail "$ingress_ip:53 already bound by something other than mihomo"
  fi
  log "preflight: $ingress_ip:53 free"

  # api.listen must be free. Defaults to loopback:18080; verify whatever the
  # operator picked. Same sed pattern as above — accepts quoted or unquoted.
  api_addr=$(sed -nE 's/^[[:space:]]*listen:[[:space:]]*"?([^"#[:space:]]+)"?.*/\1/p' "$yaml" | head -1)
  if [ -n "$api_addr" ]; then
    api_port=${api_addr##*:}
    if ss -tulnp 2>/dev/null | grep -E ":${api_port}\b" | grep -v turnout-gateway >/dev/null; then
      ss -tulnp "sport = :${api_port}" >&2
      fail "api.listen ${api_addr} already bound by another process — pick a free port in gateway.yaml"
    fi
    log "preflight: api.listen $api_addr free"
  fi

  # ── Return path ─────────────────────────────────────────────────────────
  #
  # The firewall's address must be reachable on the ingress segment before we
  # install a default route through it. Getting this wrong takes the node off
  # the network entirely (default route to nowhere), so verify first.
  if ping -c 1 -W 2 -I "$ingress_iface" "$return_gw" >/dev/null 2>&1; then
    log "preflight: return gateway $return_gw reachable on $ingress_iface"
  else
    log "preflight: WARNING — return gateway $return_gw did not answer ICMP on $ingress_iface."
    log "preflight:           That is not fatal (many firewalls drop ICMP), but confirm it is the"
    log "preflight:           right address: the default route will point at it."
  fi

  # Do not collide with upstream's table ip nat if both are present.
  if nft list table ip nat >/dev/null 2>&1 \
     && ! nft list table ip nat | grep -q FEILIAN_; then
    log "preflight: note — table ip nat exists without FEILIAN_ chains (another NAT ruleset is present)"
  fi

  log "preflight: all good"
}

# ---------------------------------------------------------------------------
# 2. Install mihomo data-plane binary

install_mihomo() {
  if [ -x "$SCRIPT_DIR/mihomo" ]; then
    install -m 0755 "$SCRIPT_DIR/mihomo" /usr/local/bin/mihomo
    log "mihomo installed from $SCRIPT_DIR/mihomo"
  elif [ -x /usr/local/bin/mihomo ]; then
    log "mihomo already installed at /usr/local/bin/mihomo"
  else
    log "downloading mihomo ${MIHOMO_VERSION} compatible build (set MIHOMO_VERSION to override)"
    arch=$(uname -m)
    case "$arch" in
      x86_64)  go_arch=amd64 ;;
      aarch64) go_arch=arm64 ;;
      *) fail "unsupported arch: $arch" ;;
    esac
    # Use the "compatible" variant — works on CPUs without AMD64-v3 (avx2),
    # which several older forwarding-node hardware classes lack.
    pkg="mihomo-linux-${go_arch}-compatible-v${MIHOMO_VERSION}"
    url="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/${pkg}.gz"
    tmp=$(mktemp -d)
    log "fetching $url"
    curl -fsSL "$url" -o "$tmp/m.gz" \
      || fail "could not download mihomo; place a binary at $SCRIPT_DIR/mihomo and rerun"
    gunzip "$tmp/m.gz"
    install -m 0755 "$tmp/m" /usr/local/bin/mihomo
    rm -rf "$tmp"
  fi
  # Capture full output then take first line in shell — avoids SIGPIPE
  # from `head -1` closing the pipe early under `set -o pipefail` (mihomo
  # -v emits 2 lines, the second triggers SIGPIPE → pipefail propagates
  # exit 141 and the install aborts).
  v=$(/usr/local/bin/mihomo -v 2>&1)
  v=${v%%$'\n'*}
  log "mihomo: $v"
}

# ---------------------------------------------------------------------------
# 3. (removed) sing-box CLI install.
#
# Upstream installed /usr/local/bin/sing-box purely as a helper for
# whitelistexpand's `rule-set decompile` step. That package was deleted along
# with the upstream console integration, so nothing on this node shells out to
# sing-box and no second binary is shipped. mihomo reads .mrs rule-sets
# directly (see internal/mihomo/rules.go).

# ---------------------------------------------------------------------------
# 4. Install turnout-gateway binary + config

install_turnout() {
  [ -x "$SCRIPT_DIR/turnout-gateway" ] \
    || fail "missing turnout-gateway binary in $SCRIPT_DIR (build with GOOS=linux go build ./cmd/gateway)"
  install -m 0755 "$SCRIPT_DIR/turnout-gateway" /usr/local/bin/turnout-gateway
  log "turnout-gateway installed"

  # Working dirs.
  install -d -m 0755 /etc/turnout /var/lib/turnout
  install -d -m 0755 /var/lib/turnout/mihomo /var/lib/turnout/mihomo/rule-sets

  if [ -f "$SCRIPT_DIR/gateway.yaml" ]; then
    # Auto-backup whatever is currently at /etc/turnout/gateway.yaml before
    # overwriting. Cheap insurance — the staged yaml may have schema /
    # field drift from the on-node copy (saw this on 92's 2026-06-07
    # mihomo cutover), and operators were doing manual `sudo cp` for
    # rollback. Now it's automatic. Backups are 0640 root:root, never
    # pruned automatically — operators clean up when they need the disk.
    if [ -f /etc/turnout/gateway.yaml ]; then
      bak=/etc/turnout/gateway.yaml.bak.$(date -u +%Y%m%d-%H%M%S)
      install -m 0640 /etc/turnout/gateway.yaml "$bak"
      log "backed up existing gateway.yaml → $bak"
    fi
    install -m 0640 "$SCRIPT_DIR/gateway.yaml" /etc/turnout/gateway.yaml
    log "gateway.yaml installed (edit /etc/turnout/gateway.yaml + restart turnout-gateway to update)"
  elif [ ! -f /etc/turnout/gateway.yaml ]; then
    fail "no gateway.yaml provided in $SCRIPT_DIR and none exists at /etc/turnout/gateway.yaml"
  else
    log "keeping existing /etc/turnout/gateway.yaml (no gateway.yaml in $SCRIPT_DIR)"
  fi

  # Generate /etc/turnout/env — runtime variables sourced by iproute.sh so it
  # can set up TPROXY rules with the correct subnet and port without needing
  # to parse YAML itself.
  #
  # Use `turnout-gateway --print-env` instead of grep/awk: YAML parsing in shell
  # is fragile (indent, quoting, comments all affect text matching). The
  # binary parses with the same logic as the runtime, so there are no
  # mismatches. install.sh runs AFTER the binary is installed (step 4), so
  # the binary is available.
  if ! /usr/local/bin/turnout-gateway --config /etc/turnout/gateway.yaml --print-env > /etc/turnout/env 2>&1; then
    fail "turnout-gateway --print-env failed — check gateway.yaml"
  fi
  chmod 0644 /etc/turnout/env
  # shellcheck disable=SC1091
  source /etc/turnout/env
  log "env file written: subnet=${TURNOUT_CLIENT_SUBNET:-?} tproxy_port=${TURNOUT_TPROXY_PORT:-0} ingress=${TURNOUT_INGRESS_IFACE:-?}"

  # rule-sets — baked into the tarball by stage.sh. Mostly MetaCubeX .mrs,
  # but the ad lists (anti-ad.txt, cname-ads.txt) and pool rule_lists
  # (<tag>.list) are plain text; copying only *.mrs leaves those providers
  # pointing at nonexistent files, and mihomo only logs an error and keeps
  # serving — the rules silently match nothing.
  if [ -d "$SCRIPT_DIR/rule-sets" ]; then
    n=$(find "$SCRIPT_DIR/rule-sets" -maxdepth 1 -type f | wc -l | tr -d ' ')
    if [ "$n" -gt 0 ]; then
      install -m 0644 "$SCRIPT_DIR"/rule-sets/* /var/lib/turnout/mihomo/rule-sets/
      log "rule-sets installed ($n files in /var/lib/turnout/mihomo/rule-sets/)"
    fi
  fi

  # mihomo's geoip.metadb (used by the geoip-cn routing rule). If staged,
  # drop in the working dir; otherwise leave for mihomo to download on
  # first start (works only when turnout-gateway has already routed mihomo's
  # HTTP fetches through itself, chicken-and-egg).
  if [ -f "$SCRIPT_DIR/geoip.metadb" ]; then
    install -m 0644 "$SCRIPT_DIR/geoip.metadb" /var/lib/turnout/mihomo/geoip.metadb
    log "geoip.metadb installed for mihomo"
  fi

  # Sanity: rule-sets must be present.
  compgen -G "/var/lib/turnout/mihomo/rule-sets/*.mrs" >/dev/null \
    || fail "no .mrs files in /var/lib/turnout/mihomo/rule-sets/ — re-run scripts/stage.sh"
  [ -f /var/lib/turnout/mihomo/geoip.metadb ] \
    || log "WARNING: mihomo geoip.metadb missing; mihomo will fail to start until it downloads one"
}

# ---------------------------------------------------------------------------
# 5. Render nft + install policy-routing helper

install_nft() {
  # YAML-aware values from the binary's own parser; never grep YAML again
  # for the same fields — install_turnout's env and install_nft's nft.conf
  # MUST agree, and re-parsing risks divergence on indent/quote edge cases.
  # shellcheck disable=SC1091
  source /etc/turnout/env
  [ -n "${TURNOUT_CLIENT_SUBNET:-}" ] || fail "TURNOUT_CLIENT_SUBNET missing in /etc/turnout/env (re-run install_turnout)"
  [ -n "${TURNOUT_API_PORT:-}" ]      || fail "TURNOUT_API_PORT missing in /etc/turnout/env (re-run install_turnout)"
  [ -n "${TURNOUT_INGRESS_IFACE:-}" ] || fail "TURNOUT_INGRESS_IFACE missing in /etc/turnout/env (re-run install_turnout)"

  # Rendering lives in render-rules.sh, not here: the control plane re-renders
  # after PUT /api/node/network and must not carry a second copy of this
  # logic. Install the script + template first, then invoke it.
  install -m 0755 "$SCRIPT_DIR/render-rules.sh" /etc/turnout/render-rules.sh
  install -m 0644 "$SCRIPT_DIR/nft.conf.tmpl"    /etc/turnout/nft.conf.tmpl
  /etc/turnout/render-rules.sh \
    || fail "render-rules.sh failed — see its output above"
  log "nft.conf rendered (ingress_iface=$TURNOUT_INGRESS_IFACE, client_subnet=$TURNOUT_CLIENT_SUBNET, api_port=$TURNOUT_API_PORT, api_allow_from='${TURNOUT_API_ALLOW_FROM:-<loopback only>}')"

  install -m 0755 "$SCRIPT_DIR/iproute.sh" /etc/turnout/iproute.sh
  log "iproute.sh installed"
}

# ---------------------------------------------------------------------------
# 5b. Install the return route through the firewall.
#
# This is the entire "hand unproxied traffic back" mechanism (PLAN.md P2,
# 方案 B). The classifier re-originates DIRECT flows from this host; without
# a default route pointing at the firewall they would leave through the
# egress NIC instead, defeating the bypass design and bypassing whatever
# policy the firewall applies to normal office egress.
#
# Idempotency: `ip route replace` overwrites an existing default route.
# We deliberately do NOT delete the old default route first — a gap between
# delete and add would black-hole the node's own management traffic.
#
# Persistence: this writes a systemd-networkd drop-in if networkd manages
# the ingress link, and a distro-agnostic ip-route.service as a backstop.
# The route is re-asserted on every install run regardless.
install_return_route() {
  # shellcheck disable=SC1091
  source /etc/turnout/env
  [ -n "${TURNOUT_RETURN_GATEWAY:-}" ] \
    || fail "TURNOUT_RETURN_GATEWAY missing in /etc/turnout/env (set node.return.gateway_ip and re-run)"

  # Refuse to point the default route at ourselves — that is an immediate
  # loop, and it is an easy typo (return.gateway_ip vs node.ingress_ip).
  if [ "${TURNOUT_RETURN_GATEWAY}" = "${TURNOUT_INGRESS_IP:-}" ]; then
    fail "node.return.gateway_ip == node.ingress_ip ($TURNOUT_RETURN_GATEWAY) — the default route must point at the FIREWALL, not at this host"
  fi

  # Gateway must be on-link for the ingress interface, or the route is
  # unusable. Check without altering anything.
  if ! ip route get "$TURNOUT_RETURN_GATEWAY" >/dev/null 2>&1; then
    fail "return gateway $TURNOUT_RETURN_GATEWAY is unreachable per the routing table — check node.return.gateway_ip"
  fi

  local dev_arg=""
  if [ -n "${TURNOUT_RETURN_IFACE:-}" ]; then
    dev_arg="dev ${TURNOUT_RETURN_IFACE}"
  fi

  log "installing default route: via $TURNOUT_RETURN_GATEWAY ${dev_arg:-dev auto}"
  # shellcheck disable=SC2086
  ip route replace default via "$TURNOUT_RETURN_GATEWAY" $dev_arg \
    || fail "failed to install default route via $TURNOUT_RETURN_GATEWAY"

  # Verify it actually took effect and points where we think.
  local now
  now=$(ip route show default | head -1)
  log "default route now: ${now:-<none>}"

  # Persist across reboots. Prefer networkd when it owns the link (it will
  # otherwise flush foreign routes — the same class of problem assert.go was
  # written for); fall back to a small oneshot unit.
  if systemctl is-enabled systemd-networkd.service >/dev/null 2>&1; then
    install -d -m 0755 /etc/systemd/network
    cat > /etc/systemd/network/10-turnout-return.network <<EOF
# Written by turnout-gateway install.sh — DO NOT EDIT BY HAND.
#
# Pins the default route at the firewall. The bypass role depends on this:
# traffic the classifier sends DIRECT is re-originated from this host and
# must land on the firewall rather than the internet.
[Match]
Name=${TURNOUT_INGRESS_IFACE}

[Network]
DHCP=no

[Route]
Gateway=${TURNOUT_RETURN_GATEWAY}
Destination=0.0.0.0/0
Metric=100
EOF
    log "persisted return route via /etc/systemd/network/10-turnout-return.network"
    systemctl reload-or-restart systemd-networkd.service 2>/dev/null || true
  else
    cat > /etc/systemd/system/turnout-return-route.service <<EOF
# Written by turnout-gateway install.sh — DO NOT EDIT BY HAND.
[Unit]
Description=turnout-gateway return default route (via firewall)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'ip route replace default via ${TURNOUT_RETURN_GATEWAY} ${dev_arg:+dev ${TURNOUT_RETURN_IFACE}}'

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable turnout-return-route.service >/dev/null 2>&1 || true
    log "persisted return route via turnout-return-route.service"
  fi
}

# ---------------------------------------------------------------------------
# 6. Install systemd units + logrotate, enable, start

install_units() {
  # turnout-mihomo / turnout-gateway / turnout-nft. This is a greenfield
  # deployment target, so upstream's legacy engine cleanup block is
  # dropped — no node here ever carried that unit.
  for unit in turnout-mihomo.service turnout-gateway.service turnout-nft.service; do
    [ -f "$SCRIPT_DIR/$unit" ] || continue
    install -m 0644 "$SCRIPT_DIR/$unit" "/etc/systemd/system/$unit"
  done
  install -m 0644 "$SCRIPT_DIR/logrotate-turnout.conf" /etc/logrotate.d/turnout
  systemctl daemon-reload
  log "systemd units installed"
}

# ---------------------------------------------------------------------------
# 7. Pre-render mihomo config so the first start finds a valid file.
# Without this, mihomo's parse fails on first boot and the unit fail-
# restarts for ~5s until turnout-gateway has had a chance to write the
# bootstrap config — harmless but noisy in logs.

prerender_config() {
  /usr/local/bin/turnout-gateway --config /etc/turnout/gateway.yaml --render-once \
    || fail "turnout-gateway --render-once failed; check gateway.yaml"
  log "bootstrap mihomo config rendered at /var/lib/turnout/mihomo/config.yaml"
  # mihomo -t: validate the rendered YAML before accepting it.
  # Catches config bugs (invalid rule-provider paths, bad proxy syntax) that
  # render-once won't catch — render-once only verifies the renderer produces
  # valid Go structs, not that mihomo itself can parse the output.
  /usr/local/bin/mihomo -d /var/lib/turnout/mihomo -t \
    || fail "mihomo -t failed on rendered config — check gateway.yaml and rule-sets"
  log "mihomo -t passed"
}

start_services() {
  log "enabling + starting turnout-mihomo + turnout-gateway"
  # Use enable + restart (not enable --now). `enable --now` is a no-op for
  # services already running — so a re-install with new binaries / new
  # gateway.yaml would silently keep the old processes alive. Explicit
  # restart ensures the units pick up whatever this run just installed.
  systemctl daemon-reload
  systemctl enable turnout-mihomo.service turnout-gateway.service turnout-nft.service
  systemctl restart turnout-mihomo.service
  # turnout-nft has PartOf=turnout-mihomo.service so it auto-restarts when
  # mihomo does, but be explicit in case the unit file dependency changed
  # this run (daemon-reload + restart picks up new After=/BindsTo=).
  systemctl restart turnout-nft.service
  systemctl restart turnout-gateway.service

  systemctl --no-pager status turnout-mihomo.service turnout-gateway.service turnout-nft.service \
    | head -30 || true
}

# ---------------------------------------------------------------------------
main() {
  if [ "$SKIP_PRECHECK" = "0" ]; then
    precheck
  else
    log "SKIP_PRECHECK=1 — skipping preflight"
  fi
  install_mihomo
  install_turnout
  install_nft
  install_return_route
  install_units
  prerender_config
  start_services
  log "DONE — verify with 'systemctl status turnout-*' and 'journalctl -fu turnout-mihomo'"
}

main "$@"
