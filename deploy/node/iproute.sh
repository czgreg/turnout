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
DNS_CHAIN="TURNOUT_DNS"
INGRESS_IP="${TURNOUT_INGRESS_IP:-}"
DNS_HIJACK="${TURNOUT_DNS_HIJACK:-1}"

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

# purge_prerouting deletes every PREROUTING rule this script owns on the
# ingress interface — the jump into $CHAIN and the API DROP — regardless of
# which source subnet wrote them. Scoped to -i "$INGRESS_IFACE" and this
# chain/port so it cannot touch an operator's unrelated rules.
purge_prerouting() {
    local src
    # DNS hijack jumps live in the nat table; same stale-subnet problem.
    for src in $(iptables -t nat -S PREROUTING 2>/dev/null \
        | awk -v ifc="$INGRESS_IFACE" -v ch="$DNS_CHAIN" '
            $1=="-A" && $2=="PREROUTING" && $0 ~ "-j "ch {
                for (i=1;i<=NF;i++) {
                    if ($i=="-s") s=$(i+1);
                    if ($i=="-i") f=$(i+1);
                }
                if (f==ifc && s!="") print s
            }' | sort -u); do
        while iptables -t nat -D PREROUTING -i "$INGRESS_IFACE" -s "$src" \
            -j "$DNS_CHAIN" 2>/dev/null; do :; done
    done
    # Jump rules: "-A PREROUTING -s <subnet> -i <iface> ... -j TURNOUT_TPROXY"
    for src in $(iptables -t mangle -S PREROUTING \
        | awk -v ifc="$(printf '%s' "$INGRESS_IFACE")" -v ch="$CHAIN" '
            $1=="-A" && $2=="PREROUTING" && $0 ~ "-j "ch {
                for (i=1;i<=NF;i++) {
                    if ($i=="-s") s=$(i+1);
                    if ($i=="-i") f=$(i+1);
                }
                if (f==ifc && s!="") print s
            }' | sort -u); do
        while iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" -s "$src" \
            -j "$CHAIN" 2>/dev/null; do :; done
    done
    # API deny rules: same scoping, keyed on the drop target.
    for src in $(iptables -t mangle -S PREROUTING \
        | awk -v ifc="$INGRESS_IFACE" -v port="$API_PORT" '
            $1=="-A" && $2=="PREROUTING" && $0 ~ /--dst-type LOCAL/ \
            && $0 ~ ("--dport " port) && $0 ~ /-j DROP/ {
                for (i=1;i<=NF;i++) {
                    if ($i=="-s") s=$(i+1);
                    if ($i=="-i") f=$(i+1);
                }
                if (f==ifc && s!="") print s
            }' | sort -u); do
        while iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" -s "$src" \
            -m addrtype --dst-type LOCAL -p tcp --dport "$API_PORT" -j DROP 2>/dev/null; do :; done
    done
}

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

    # Packets addressed to THIS HOST are never proxied.
    #
    # TPROXY keyed on (ingress iface, source subnet) alone is too broad: an
    # office terminal connecting to this box's own SSH / DNS / any local
    # service matches both, and would be handed to mihomo instead of the
    # local socket. The match is on the ORIGINAL destination, which is still
    # intact here (TPROXY rewrites it only for packets that reach the target).
    #
    # This is what makes a single-NIC deployment safe: traffic that merely
    # passes through is proxied, traffic that terminates on the box is not.
    # It also covers the liveness address when the watchdog has it up on lo.
    iptables -t mangle -A "$CHAIN" -m addrtype --dst-type LOCAL -j RETURN

    # With DNS hijack on, TCP 53 must stay out of TPROXY so the nat chain
    # below can DNAT it to mihomo's DNS listener. Without this the query
    # would be accepted by mihomo as an opaque TCP flow to 119.29.29.29 and
    # forwarded as-is — answered by whichever resolver the client chose.
    if [ "$DNS_HIJACK" = "1" ]; then
        iptables -t mangle -A "$CHAIN" -p tcp --dport 53 -j RETURN
    fi

    # Redirect non-DNS TCP from the diverted segment to mihomo's tproxy-port.
    # (Local-destined traffic already returned above, which is also why DNS
    # over TCP to ingress_ip:53 needs no explicit exclusion here.)
    iptables -t mangle -A "$CHAIN" -p tcp \
        -j TPROXY --on-port "$TPROXY_PORT" --on-ip 127.0.0.1 \
        --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"

    # Redirect non-DNS UDP from the diverted segment to mihomo's tproxy-port.
    # Exclude DNS (port 53) — DNS is accepted by nft and delivered to
    # mihomo's DNS server directly, so it must not be intercepted here.
    iptables -t mangle -A "$CHAIN" -p udp ! --dport 53 \
        -j TPROXY --on-port "$TPROXY_PORT" --on-ip 127.0.0.1 \
        --tproxy-mark "$TPROXY_MARK/$TPROXY_MARK"

    # Stale rules from a previous client_subnet must go first. Deleting by
    # the CURRENT "$CLIENT_SUBNET" only ever matches rules written by the
    # same config, so widening or narrowing the subnet used to leave the old
    # jump/DROP in place next to the new one: traffic from both segments was
    # intercepted (or denied) and only the new one was reported anywhere.
    # Seen 2026-10-22 when 10.1.3.0/24 -> 192.168.0.0/16 left the /24 jump
    # live and the /16 terminals still un-intercepted.
    purge_prerouting

    # No API-port DROP here any more (removed 2026-10-22).
    #
    # It used to deny client_subnet -> this node's API port so terminals
    # could not reach the control plane. That made the management UI
    # unreachable from exactly the segment operators sit in: when
    # client_subnet was 192.168.0.0/16, the admin laptop was inside it and
    # got silently dropped while the process listened fine (seen on
    # 10.1.3.15). Operators then had to tunnel over ssh just to look at
    # /ui/.
    #
    # The DROP was also redundant: the TPROXY chain's first rule returns on
    # `--dst-type LOCAL`, so packets addressed to this host never reach
    # mihomo in the first place. Local-destined traffic is delivered by the
    # kernel; nft's input chain accepts tcp dport $API_PORT.
    #
    # purge_prerouting() above still removes stale DROP rules left by older
    # installs, so upgrading cleans them up.

    # Attach to PREROUTING: apply TPROXY only to traffic that arrived FROM
    # the firewall on the ingress interface, from the diverted segment.
    # Both matches matter — see the header note on the DIRECT path.
    iptables -t mangle -A PREROUTING -i "$INGRESS_IFACE" -s "$CLIENT_SUBNET" \
        -j "$CHAIN"

    dns_hijack_up

    echo "turnout tproxy up: $CLIENT_SUBNET@$INGRESS_IFACE -> 127.0.0.1:$TPROXY_PORT (fwmark $TPROXY_MARK)"
}

# dns_hijack_up captures DNS the firewall diverts here and hands it to
# mihomo's DNS listener, so terminals can keep their own resolvers
# (223.5.5.5, 119.29.29.29 …) unchanged. See DNSConfig.Hijack.
#
# Mechanics: the packet arrives with dst=<resolver>:53. DNAT in nat
# PREROUTING rewrites dst to INGRESS_IP:53; conntrack un-NATs the reply so
# the terminal sees the answer coming from the resolver it asked. Local
# destinations RETURN first: a terminal that already points at INGRESS_IP
# needs no rewrite, and SSH/API must never be touched.
#
# mihomo's own upstream queries originate on this host (OUTPUT), so they
# never traverse PREROUTING and cannot be hijacked back into ourselves.
dns_hijack_up() {
    iptables -t nat -N "$DNS_CHAIN" 2>/dev/null || iptables -t nat -F "$DNS_CHAIN"
    if [ "$DNS_HIJACK" != "1" ]; then
        echo "turnout dns hijack: disabled (data_plane.dns.hijack=false)"
        return 0
    fi
    [ -n "$INGRESS_IP" ] || { echo "TURNOUT_INGRESS_IP not set — cannot DNAT DNS" >&2; return 1; }
    iptables -t nat -A "$DNS_CHAIN" -m addrtype --dst-type LOCAL -j RETURN
    iptables -t nat -A "$DNS_CHAIN" -p udp --dport 53 -j DNAT --to-destination "$INGRESS_IP:53"
    iptables -t nat -A "$DNS_CHAIN" -p tcp --dport 53 -j DNAT --to-destination "$INGRESS_IP:53"
    iptables -t nat -A PREROUTING -i "$INGRESS_IFACE" -s "$CLIENT_SUBNET" -j "$DNS_CHAIN"
    echo "turnout dns hijack: $CLIENT_SUBNET@$INGRESS_IFACE :53 -> $INGRESS_IP:53"
}

tproxy_down() {
    # Remove the API deny rule before removing the generic TPROXY jump.
    while iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" \
        -s "$CLIENT_SUBNET" -m addrtype --dst-type LOCAL \
        -p tcp --dport "$API_PORT" -j DROP 2>/dev/null; do :; done

    # Remove PREROUTING jump rule.
    iptables -t mangle -D PREROUTING -i "$INGRESS_IFACE" -s "$CLIENT_SUBNET" \
        -j "$CHAIN" 2>/dev/null || true

    # DNS hijack: jump(s) for any subnet, then the chain.
    purge_prerouting
    iptables -t nat -F "$DNS_CHAIN" 2>/dev/null || true
    iptables -t nat -X "$DNS_CHAIN" 2>/dev/null || true

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
