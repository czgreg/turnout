#!/bin/bash
# turnout-gateway transparent proxy routing (TPROXY mode) — bypass role.
#
# Called by turnout-nft.service on ExecStart (up) and ExecStop (down).
# Idempotent on both directions.
#
# What it sets up:
#   - iptables TPROXY rules: redirect non-DNS TCP/UDP that arrived on the
#     ingress interface from the office subnet to mihomo's tproxy-port
#     (7893). The kernel's TPROXY target preserves the original client
#     sourceIP, so mihomo's /connections metadata shows real per-terminal
#     IPs — unlike TUN mode which collapses everything to 198.18.0.0 and
#     would break per-terminal egress pinning.
#   - ip rule + ip route: route TPROXY-marked packets (fwmark 0x44) to
#     local (lo), so the kernel delivers them to mihomo's tproxy socket.
#
# What it deliberately does NOT do (bypass-role specifics):
#   - It does not touch the FORWARD chain. Traffic that the classifier sends
#     DIRECT is re-originated by mihomo (which dials out through the default
#     route into the firewall); packets we merely forward would otherwise be
#     at risk of being re-captured. Keeping TPROXY confined to PREROUTING
#     input from the ingress interface is what makes the return path safe.
#   - It does not install the default route. install.sh does that, because it
#     needs to happen once at deploy time rather than on every rule reload —
#     see install_return_route().
#
# Configuration is read from /etc/turnout/env (written by install.sh):
#   TURNOUT_CLIENT_SUBNET    office segment CIDR the firewall diverts, e.g. 10.1.0.0/16
#   TURNOUT_TPROXY_PORT      mihomo tproxy-port, e.g. 7893
#   TURNOUT_INGRESS_IFACE    NIC carrying diverted traffic, e.g. ens19
#   TURNOUT_INGRESS_IP       our address on that NIC (the PBR next-hop)
#   TURNOUT_API_PORT         control-plane API port, for the early deny

set -euo pipefail

ENV_FILE="/etc/turnout/env"
[ -f "$ENV_FILE" ] && source "$ENV_FILE"

CLIENT_SUBNET="${TURNOUT_CLIENT_SUBNET:-}"
TPROXY_PORT="${TURNOUT_TPROXY_PORT:-0}"
INGRESS_IFACE="${TURNOUT_INGRESS_IFACE:-}"
API_PORT="${TURNOUT_API_PORT:-18080}"
TPROXY_MARK="0x44"
TPROXY_TABLE="101"
CHAIN="TURNOUT_TPROXY"

[ -n "$CLIENT_SUBNET" ] || { echo "TURNOUT_CLIENT_SUBNET not set in $ENV_FILE" >&2; exit 1; }
# The ingress interface is what scopes every rule below. Without it we would
# have to match on source alone, and the DIRECT path (which mihomo re-originates
# from this host) could match and loop.
[ -n "$INGRESS_IFACE" ] || { echo "TURNOUT_INGRESS_IFACE not set in $ENV_FILE" >&2; exit 1; }
# TPROXY is the production data path; tproxy_port=0 means gateway.yaml is
# misconfigured (TUN-only mode is not supported — it collapses all client
# sourceIPs to 198.18.0.0). Fail fast rather than installing a rule that
# targets port 0.
[ "$TPROXY_PORT" -gt 0 ] 2>/dev/null \
    || { echo "TURNOUT_TPROXY_PORT=$TPROXY_PORT — set data_plane.tproxy_port (e.g. 7893) in /etc/turnout/gateway.yaml and re-run install.sh" >&2; exit 1; }
[ "$API_PORT" -gt 0 ] 2>/dev/null \
    || { echo "TURNOUT_API_PORT=$API_PORT — set api.listen to a valid port in /etc/turnout/gateway.yaml and re-run install.sh" >&2; exit 1; }

tproxy_up() {
    # Ensure xt_TPROXY module is loaded.
    modprobe xt_TPROXY 2>/dev/null || true

    # ip rule: TPROXY-marked packets → local routing table 101.
    while ip rule del fwmark "$TPROXY_MARK" lookup "$TPROXY_TABLE" 2>/dev/null; do :; done
    ip rule add fwmark "$TPROXY_MARK" lookup "$TPROXY_TABLE" pref 101

    # ip route: all destinations in table 101 go to loopback (local delivery).
    ip route flush table "$TPROXY_TABLE" 2>/dev/null || true
    ip route add local 0.0.0.0/0 dev lo table "$TPROXY_TABLE"

    # iptables TPROXY chain (idempotent: flush + re-add).
    iptables -t mangle -N "$CHAIN" 2>/dev/null || iptables -t mangle -F "$CHAIN"

    # Redirect non-DNS TCP from the diverted segment to mihomo's tproxy-port.
    iptables -t mangle -A "$CHAIN" -p tcp \
        -j TPROXY --on-port "$TPROXY_PORT" --on-ip 127.0.0.1 \
        --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"

    # Redirect non-DNS UDP from the diverted segment to mihomo's tproxy-port.
    # Exclude DNS (port 53) — DNS is accepted by nft and delivered to
    # mihomo's DNS server directly, so it must not be intercepted here.
    iptables -t mangle -A "$CHAIN" -p udp ! --dport 53 \
        -j TPROXY --on-port "$TPROXY_PORT" --on-ip 127.0.0.1 \
        --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"

    # Block diverted office terminals from reaching the gateway API before
    # the generic TPROXY jump. Without this early drop, mihomo can accept a
    # terminal's connection to our own API port before the inet/turnout input
    # chain sees it, bypassing the source deny in nft.conf.
    #
    # Note the source match is the configured subnet rather than a hardcoded
    # one (upstream hardcoded its VPN pool).
    while iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" \
        -s "$CLIENT_SUBNET" -m addrtype --dst-type LOCAL \
        -p tcp --dport "$API_PORT" -j DROP 2>/dev/null; do :; done
    iptables -t mangle -I PREROUTING 1 -i "$INGRESS_IFACE" \
        -s "$CLIENT_SUBNET" -m addrtype --dst-type LOCAL \
        -p tcp --dport "$API_PORT" -j DROP

    # Attach to PREROUTING: apply TPROXY only to traffic that arrived FROM
    # the firewall on the ingress interface, from the diverted segment.
    # Both matches matter — see the header note on the DIRECT path.
    # Idempotent: delete existing rule before adding.
    iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" -s "$CLIENT_SUBNET" \
        -j "$CHAIN" 2>/dev/null || true
    iptables -t mangle -A PREROUTING -i "$INGRESS_IFACE" -s "$CLIENT_SUBNET" \
        -j "$CHAIN"

    echo "turnout tproxy up: $CLIENT_SUBNET@$INGRESS_IFACE -> 127.0.0.1:$TPROXY_PORT (fwmark $TPROXY_MARK)"
}

tproxy_down() {
    # Remove the API deny rule before removing the generic TPROXY jump.
    while iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" \
        -s "$CLIENT_SUBNET" -m addrtype --dst-type LOCAL \
        -p tcp --dport "$API_PORT" -j DROP 2>/dev/null; do :; done

    # Remove PREROUTING jump rule.
    iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" -s "$CLIENT_SUBNET" \
        -j "$CHAIN" 2>/dev/null || true

    # Flush and remove the chain.
    iptables -t mangle -F "$CHAIN" 2>/dev/null || true
    iptables -t mangle -X "$CHAIN" 2>/dev/null || true

    # Remove ip rule and flush routing table.
    while ip rule del fwmark "$TPROXY_MARK" lookup "$TPROXY_TABLE" 2>/dev/null; do :; done
    ip route flush table "$TPROXY_TABLE" 2>/dev/null || true

    echo "turnout tproxy down: $CLIENT_SUBNET cleared"
}

case "${1:-up}" in
  up)   tproxy_up ;;
  down) tproxy_down ;;
  *)    echo "usage: $0 {up|down}" >&2; exit 2 ;;
esac
