#!/usr/bin/env bash
# verify-bypass.sh — acceptance checks for a bypass-role node.
#
# Runs ON the node (needs ip / nft / iptables and the local API). It is
# designed to be piped over ssh rather than copied:
#
#   ssh -t ops@<host> 'sudo bash -s' < scripts/verify-bypass.sh
#   make verify NODE=ops@<host>
#
# WHY THIS EXISTS
#
# The failure modes this deployment has are mostly SILENT. A classifier that
# sends everything DIRECT still passes traffic; a proxy dial that follows the
# default route into the firewall still eventually connects; a watchdog that
# never withdraws its address still answers pings. None of those produce an
# error — they produce "the proxy is slow" or "it works for me".
#
# So every check below asserts an OBSERVABLE CONSEQUENCE, not a configuration
# value:
#   - the return route is compared against the configured firewall address
#   - proxied traffic is compared against direct traffic by EXIT IP
#   - the liveness address is compared against what the kernel reports
#
# Exit code = number of FAILED checks (0 = all good). SKIP is not a failure:
# a check whose prerequisite is absent (no token configured, no jq, the
# whitelist target unreachable from this vantage point) is reported as SKIP
# with the reason, never as PASS.
#
# Env:
#   TURNOUT_TOKEN    API bearer token. Default: read from api.token_file
#                    (/var/lib/turnout/api-token). Without either, the
#                    authenticated checks report SKIP, not PASS.
#   DIRECT_TARGET    a domestic URL expected to go DIRECT (default baidu.com)
#   PROXY_TARGET     a whitelisted overseas URL expected to be PROXIED
#                    (default https://api.anthropic.com/ — must be on YOUR
#                    whitelist; the check reports SKIP if it is not)
#   IP_ECHO          URL returning the caller's public IP as plain text
#                    (default https://api.ipify.org)
#   CLIENT_IP        a terminal IP behind the firewall, for the per-terminal
#                    assignment checks
#
# The firewall-side configuration cannot be checked from here; the script
# prints it as a reminder list at the end rather than pretending to verify it.

set -uo pipefail

ENV_FILE="${ENV_FILE:-/etc/turnout/env}"
DIRECT_TARGET="${DIRECT_TARGET:-http://www.baidu.com/}"
PROXY_TARGET="${PROXY_TARGET:-https://api.anthropic.com/}"
IP_ECHO="${IP_ECHO:-https://api.ipify.org}"
CLIENT_IP="${CLIENT_IP:-}"
PROXY_URL="http://127.0.0.1:11080"

PASS=0
FAIL=0
SKIP=0
FAILED_NAMES=()

# ── output ──────────────────────────────────────────────────────────────────

ok()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
bad()  { FAIL=$((FAIL+1)); FAILED_NAMES+=("$*"); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
skip() { SKIP=$((SKIP+1)); printf '  \033[33mSKIP\033[0m  %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# api_base / api_tls — the control plane speaks HTTPS with a self-signed
# certificate (api.tls). /etc/turnout/env (sourced below) names the scheme
# and the certificate file; curl trusts exactly that file. Older env files
# without those vars fall back to plain http.
api_base() { printf '%s://127.0.0.1:%s' "${TURNOUT_API_SCHEME:-http}" "$API_PORT"; }
api_tls() {
  if [ "${TURNOUT_API_SCHEME:-http}" = "https" ] && [ -n "${TURNOUT_API_TLS_CERT:-}" ]; then
    printf -- '--cacert %s' "$TURNOUT_API_TLS_CERT"
  fi
}

# api GET → body; sets API_STATUS. Auth only when a token is provided.
api_get() {
  local path="$1"
  local -a auth=()
  [ -n "${TURNOUT_TOKEN:-}" ] && auth=(-H "Authorization: Bearer $TURNOUT_TOKEN")
  # shellcheck disable=SC2046
  API_STATUS=$(curl -s -o /tmp/.verify_body -w '%{http_code}' --max-time 8 $(api_tls) \
    "${auth[@]}" "$(api_base)${path}" 2>/dev/null)
  cat /tmp/.verify_body 2>/dev/null
}

# json_get PATH — scalar at a dotted path from /tmp/.verify_body.
# Supports one level of nesting ("primary.name"), which is what the terminal
# endpoint needs: primary/secondary are objects, and printing their repr
# would compare as a passing string while meaning nothing.
json_get() {
  local key="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$key" <<'PY' 2>/dev/null
import json,sys
try:
    d=json.load(open('/tmp/.verify_body'))
except Exception:
    sys.exit(0)
for part in sys.argv[1].split('.'):
    if not isinstance(d, dict):
        sys.exit(0)
    d = d.get(part)
    if d is None:
        sys.exit(0)
print(str(d).lower() if isinstance(d,bool) else d)
PY
  else
    # Without python3 only flat scalars are reachable; the terminal checks
    # treat an empty result as "could not read" and skip.
    grep -o "\"$key\"[[:space:]]*:[[:space:]]*[^,}]*" /tmp/.verify_body 2>/dev/null \
      | head -1 | sed 's/.*:[[:space:]]*//' | tr -d '"'
  fi
}

# json_has KEY — exit 0 when the top-level key is present and non-null.
# Needed for object-valued fields (primary/secondary): json_get would print
# a dict repr, which reads like a passing value without meaning anything.
json_has() {
  local key="$1"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$key" <<'PY' 2>/dev/null
import json,sys
try:
    d=json.load(open('/tmp/.verify_body'))
except Exception:
    sys.exit(1)
sys.exit(0 if d.get(sys.argv[1]) is not None else 1)
PY
  else
    grep -q "\"$key\"[[:space:]]*:[[:space:]]*[^n]" /tmp/.verify_body 2>/dev/null
  fi
}

# ── prerequisites ───────────────────────────────────────────────────────────

head_ "0. 前提"

if [ "$(id -u)" -ne 0 ]; then
  echo " 必须 root 运行（需要读 iptables / ip rule / 常驻内核对象）" >&2
  exit 2
fi

if [ ! -f "$ENV_FILE" ]; then
  echo " 找不到 $ENV_FILE —— 这个节点没跑过 install.sh，或 ENV_FILE 指错了" >&2
  exit 2
fi
# shellcheck disable=SC1090
source "$ENV_FILE"
# Token: TURNOUT_TOKEN wins (legacy api.token nodes); otherwise the node's
# own token file — this script runs as root, so it can read it.
if [ -z "${TURNOUT_TOKEN:-}" ] && [ -r "${TURNOUT_API_TOKEN_FILE:-/var/lib/turnout/api-token}" ]; then
  TURNOUT_TOKEN=$(tr -d '[:space:]' < "${TURNOUT_API_TOKEN_FILE:-/var/lib/turnout/api-token}")
fi

missing=0
for v in TURNOUT_CLIENT_SUBNET TURNOUT_INGRESS_IFACE TURNOUT_INGRESS_IP TURNOUT_EGRESS_IFACE TURNOUT_RETURN_GATEWAY TURNOUT_TPROXY_PORT; do
  if [ -z "${!v:-}" ]; then
    bad "env 缺少 $v（重跑 install.sh）"
    missing=1
  fi
done
[ "$missing" -eq 0 ] && ok "env 完整（$ENV_FILE）"

API_PORT="${TURNOUT_API_PORT:-18080}"
IN_IF="${TURNOUT_INGRESS_IFACE:-}"
EG_IF="${TURNOUT_EGRESS_IFACE:-}"
IN_IP="${TURNOUT_INGRESS_IP:-}"
RETURN_GW="${TURNOUT_RETURN_GATEWAY:-}"
CLIENT_SUBNET="${TURNOUT_CLIENT_SUBNET:-}"
TPROXY_PORT="${TURNOUT_TPROXY_PORT:-0}"

if command -v python3 >/dev/null 2>&1; then
  ok "python3 可用（JSON 解析）"
else
  skip "python3 缺失，JSON 解析退化为 grep（结果仍然可用，但更脆）"
fi

# ── 1. 入向链路 ─────────────────────────────────────────────────────────────

head_ "1. 入向链路（引流口）"

if [ -n "$IN_IF" ] && ip link show "$IN_IF" >/dev/null 2>&1; then
  state=$(cat "/sys/class/net/$IN_IF/operstate" 2>/dev/null || echo unknown)
  case "$state" in
    up|unknown) ok "引流口 $IN_IF 存在且 up（operstate=$state）" ;;
    *)          bad "引流口 $IN_IF 存在但 operstate=$state —— 不会有流量到达" ;;
  esac
else
  bad "引流口 ${IN_IF:-<未配置>} 不存在"
fi

if [ -n "$IN_IP" ] && ip -4 -o addr show dev "$IN_IF" 2>/dev/null \
     | awk '{print $4}' | cut -d/ -f1 | grep -qx "$IN_IP"; then
  ok "$IN_IP 已配置在 $IN_IF 上（防火墙 PBR 的下一跳）"
else
  bad "$IN_IP 未配置在 $IN_IF 上 —— 防火墙的 PBR 下一跳是死的"
fi

if [ -n "$EG_IF" ] && [ "$EG_IF" = "$IN_IF" ]; then
  # Single-NIC is a supported layout: only packets that arrive on the
  # ingress interface from client_subnet and are NOT addressed to this host
  # are proxied, and mihomo's own dials leave via OUTPUT. Said differently,
  # sharing one NIC costs isolation, not correctness.
  ok "单网卡布局：ingress = egress = $IN_IF（出站绑定同一网卡）"
elif [ -n "$EG_IF" ] && ip link show "$EG_IF" >/dev/null 2>&1; then
  ok "出口口 $EG_IF 存在且不同于引流口"
else
  bad "出口口 ${EG_IF:-<未配置>} 不存在"
fi

# ── 2. 回程 ─────────────────────────────────────────────────────────────────

head_ "2. 回程（交还防火墙）"

dr=$(ip route show default | head -1)
if [ -z "$dr" ]; then
  bad "没有默认路由 —— 判定为 DIRECT 的流量无处可去"
elif echo "$dr" | grep -q "via ${RETURN_GW}"; then
  ok "默认路由指向防火墙：$dr"
else
  bad "默认路由不指向 return.gateway_ip=$RETURN_GW：$dr"
fi

if [ "$RETURN_GW" = "$IN_IP" ]; then
  bad "return.gateway_ip 等于 ingress_ip —— 路由指向自己，必然成环"
fi

fwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
[ "$fwd" = "1" ] && ok "ip_forward=1" || bad "ip_forward=$fwd（需要 1）"

rp=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null || echo 1)
case "$rp" in
  0|2) ok "rp_filter=$rp（loose，fwmark 路由需要）" ;;
  *)   bad "rp_filter=$rp（需要 0 或 2，否则 TPROXY 包会被当 martian 丢弃）" ;;
esac

# ── 3. 内核数据面 ───────────────────────────────────────────────────────────

head_ "3. 内核数据面（TPROXY）"

if grep -q '^xt_TPROXY ' /proc/modules 2>/dev/null || modprobe -n xt_TPROXY >/dev/null 2>&1; then
  ok "xt_TPROXY 可用"
else
  bad "xt_TPROXY 不可用 —— TPROXY 数据面无法工作"
fi

if ip rule show | grep -Eq 'fwmark (0x)?44.*lookup 101|lookup 101.*fwmark (0x)?44'; then
  ok "ip rule: fwmark 0x44 → table 101 在位"
else
  bad "ip rule: fwmark 0x44 → table 101 缺失（流量会被转发出去而不是交给 mihomo）"
fi

# `ip route` prints 0.0.0.0/0 as `default`, in table 101 as `local default
# dev lo`. Accept either spelling: the assertion is that a local catch-all
# exists, not how the kernel chose to render the prefix length.
if ip route show table 101 2>/dev/null | grep -Eq '^local (default|0\.0\.0\.0/0)'; then
  ok "table 101 有 local 默认路由（TPROXY 本地投递）"
else
  bad "table 101 缺少 local 0.0.0.0/0 dev lo"
fi

if iptables -t mangle -S TURNOUT_TPROXY >/dev/null 2>&1; then
  ok "iptables 链 TURNOUT_TPROXY 存在"
  if iptables -t mangle -S TURNOUT_TPROXY | grep -q "on-port $TPROXY_PORT"; then
    ok "  TPROXY 目标端口 = $TPROXY_PORT"
  else
    bad "  TURNOUT_TPROXY 里没有 --on-port $TPROXY_PORT"
  fi
  # Without this the box proxies its own inbound connections: an office
  # terminal reaching SSH / the DNS listener from client_subnet would be
  # handed to mihomo instead of the local socket. This is the check that
  # makes a single-NIC layout safe, so it is asserted explicitly.
  if iptables -t mangle -S TURNOUT_TPROXY | grep -q -- '--dst-type LOCAL -j RETURN'; then
    ok "  本机目的地址不代理（--dst-type LOCAL -j RETURN 在位）"
  else
    bad "  TURNOUT_TPROXY 缺少 --dst-type LOCAL -j RETURN —— 登录本机的流量会被代理劫持"
  fi
else
  bad "iptables 链 TURNOUT_TPROXY 不存在（turnout-nft 没起？）"
fi

jump=$(iptables -t mangle -S PREROUTING 2>/dev/null | grep 'TURNOUT_TPROXY' | head -1)
if [ -z "$jump" ]; then
  bad "PREROUTING 没有跳到 TURNOUT_TPROXY 的规则"
else
  echo "$jump" | grep -q -- "-i $IN_IF" \
    && ok "PREROUTING 跳转按入接口限定（-i $IN_IF）" \
    || bad "PREROUTING 跳转没有限定 -i $IN_IF —— 可能捕获回程流量，成环"
  echo "$jump" | grep -q -- "-s $CLIENT_SUBNET" \
    && ok "PREROUTING 跳转按源网段限定（-s $CLIENT_SUBNET）" \
    || bad "PREROUTING 跳转没有限定 -s $CLIENT_SUBNET"
fi

if nft list table inet turnout >/dev/null 2>&1; then
  ok "nft 表 inet turnout 存在"
  nft list table inet turnout 2>/dev/null | grep -q "iifname \"$IN_IF\"" \
    && ok "  nft DNS 放行按引流口限定" \
    || bad "  nft DNS 放行没有限定 iifname \"$IN_IF\""
else
  bad "nft 表 inet turnout 不存在（turnout-nft 没起？）"
fi

# ── 4. 服务与自检 ───────────────────────────────────────────────────────────

head_ "4. 服务与自检"

for u in turnout-gateway turnout-mihomo turnout-nft; do
  s=$(systemctl is-active "$u" 2>/dev/null || true)
  [ "$s" = "active" ] && ok "$u active" || bad "$u = ${s:-unknown}"
done

# shellcheck disable=SC2046
hz_status=$(curl -s -o /tmp/.verify_hz -w '%{http_code}' --max-time 8 $(api_tls) \
  "$(api_base)/healthz" 2>/dev/null)
if [ "$hz_status" = "200" ]; then
  ok "/healthz 200（数据面断言全部通过）"
elif [ "$hz_status" = "503" ]; then
  bad "/healthz 503 —— 数据面断言失败，详见下方"
  sed -n '1,40p' /tmp/.verify_hz | grep -o '"detail":"[^"]*"' | head -4 | while read -r d; do info "$d"; done
else
  bad "/healthz 无响应（HTTP ${hz_status:-000}）"
fi

if [ -z "${TURNOUT_TOKEN:-}" ]; then
  skip "watchdog 检查需要 token：节点还没初始化（setup），或 token 文件不可读"
else
  api_get /api/watchdog/status >/dev/null
  wd_state=$(json_get state)
  if [ "$API_STATUS" = "401" ]; then
    skip "watchdog：401 —— TURNOUT_TOKEN 不对"
  elif [ -z "$wd_state" ]; then
    skip "watchdog：端点无有效响应（HTTP ${API_STATUS:-000}）"
  else
    case "$wd_state" in
      healthy)   ok "watchdog state=healthy" ;;
      unhealthy) bad "watchdog state=unhealthy —— 数据面判定不健康（见 checks）" ;;
      unknown)   skip "watchdog state=unknown（首轮自检未完成，正常启动态）" ;;
      *)         bad "watchdog state=$wd_state（未知取值）" ;;
    esac
    lv_up=$(json_get liveness_up)
    lv_ip=$(json_get liveness_ip)
    if [ -n "$lv_ip" ]; then
      # The kernel is the source of truth, not the field: they are supposed
      # to agree, and a disagreement means the status is lying.
      if ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$lv_ip"; then
        kernel_up=true
      else
        kernel_up=false
      fi
      if [ "$lv_up" = "$kernel_up" ]; then
        ok "探活地址状态自洽：$lv_ip present=$kernel_up"
      else
        bad "探活地址状态不一致：API 报 liveness_up=$lv_up，内核实际 present=$kernel_up"
      fi
      if [ "$wd_state" = "unhealthy" ]; then
        af=$(json_get auto_failover)
        if [ "$af" = "true" ]; then
          info "auto_failover=true：不健康时应已摘除地址；若 present=$kernel_up 且为 true，说明摘除失败"
        else
          info "auto_failover=false：红色判定表示【已告警但未切回】，防火墙仍在引流，需人工处理"
        fi
      fi
    fi
  fi
fi

# ── 5. 分流行为（经 loopback 代理）──────────────────────────────────────────

head_ "5. 分流行为（经 127.0.0.1:${PROXY_URL##*:}）"

if ! curl -s -o /dev/null --max-time 8 -x "$PROXY_URL" "$DIRECT_TARGET" 2>/dev/null; then
  skip "loopback 代理 $PROXY_URL 不可用（mihomo 未就绪？），跳过分流检查"
else
  ok "loopback 代理可达"

  # Exit IP as seen through the proxy. Used to tell "proxied" from "direct".
  proxied_ip=$(curl -s --max-time 12 -x "$PROXY_URL" "$IP_ECHO" 2>/dev/null | tr -d '[:space:]')
  if [ -z "$proxied_ip" ]; then
    skip "经代理取样出口 IP 失败（$IP_ECHO 不可达），无法做分流出入口对比"
  else
    info "经代理出口 IP：$proxied_ip"

    if curl -s -o /dev/null --max-time 12 -x "$PROXY_URL" "$DIRECT_TARGET" 2>/dev/null; then
      ok "国内目标可达（$DIRECT_TARGET）"
    else
      bad "国内目标不可达（$DIRECT_TARGET）—— 直连路径有问题"
    fi

    if [ -n "$PROXY_TARGET" ] && curl -s -o /dev/null --max-time 15 -x "$PROXY_URL" "$PROXY_TARGET" 2>/dev/null; then
      ok "白名单目标可达（$PROXY_TARGET）"
      # A whitelisted target must NOT exit from the node's own IP. Compare
      # against a direct sample (no proxy) taken on the egress interface.
      direct_ip=$(curl -s --max-time 10 --interface "$EG_IF" "$IP_ECHO" 2>/dev/null | tr -d '[:space:]')
      if [ -z "$direct_ip" ]; then
        skip "经 $EG_IF 直连取样失败，无法对比（这不影响上一条结论）"
      elif [ "$proxied_ip" = "$direct_ip" ]; then
        bad "白名单目标与直连出口 IP 相同（$direct_ip）—— 说明它其实是 DIRECT，白名单没生效"
      else
        ok "白名单目标确实走了不同出口（代理=$proxied_ip 直连=$direct_ip）"
      fi
    else
      skip "白名单目标不可达（$PROXY_TARGET）—— 它可能不在你的白名单里，换一个 PROXY_TARGET 再跑"
    fi
  fi
fi

# ── 6. 池与按终端分配 ───────────────────────────────────────────────────────

head_ "6. 出口池与按终端分配"

if [ -z "${TURNOUT_TOKEN:-}" ]; then
  skip "池检查需要 TURNOUT_TOKEN"
else
  api_get /api/nodes/health >/dev/null
  if [ "$API_STATUS" = "200" ]; then
    q=$(json_get qualified); t=$(json_get total)
    if [ -n "$q" ] && [ "$q" -gt 0 ] 2>/dev/null; then
      ok "池：qualified=$q / total=$t"
    else
      bad "池里没有合格节点（qualified=${q:-?} / total=${t:-?}）—— 所有翻墙流量无处可去"
    fi
  else
    bad "/api/nodes/health HTTP ${API_STATUS:-000}"
  fi

  if [ -n "$CLIENT_IP" ]; then
    api_get "/api/pool/terminal?ip=${CLIENT_IP}" >/dev/null
    if [ "$API_STATUS" = "200" ]; then
      in_sub=$(json_get in_subnet)
      p=$(json_get primary.name)
      if [ "$in_sub" = "true" ] || [ "$in_sub" = "True" ]; then
        ok "终端 $CLIENT_IP 在 client_subnet 内"
      else
        bad "终端 $CLIENT_IP 不在 client_subnet（$CLIENT_SUBNET）—— PBR 源网段配错了？"
      fi
      if [ -z "$p" ]; then
        # Without python3 the nested path is unreachable; say so rather than
        # reporting a failure the script cannot actually observe.
        skip "无法读取 primary.name（本机无 python3），跳过终端分配检查"
      else
        ok "终端分配：primary=$p"
        # Stability: the same terminal must hash to the same node every time.
        p1="$p"
        api_get "/api/pool/terminal?ip=${CLIENT_IP}" >/dev/null
        p2=$(json_get primary.name)
        [ "$p1" = "$p2" ] && ok "终端分配稳定（两次查询同一 primary）" \
                          || bad "终端分配不稳定（$p1 → $p2）—— 同一终端会漂移出口 IP"
      fi
    else
      bad "/api/pool/terminal HTTP ${API_STATUS:-000}"
    fi
  else
    skip "未提供 CLIENT_IP，跳过按终端分配检查（CLIENT_IP=10.x.x.x 再跑）"
  fi
fi

# ── 7. 渲染产物 ─────────────────────────────────────────────────────────────

head_ "7. 渲染产物（mihomo 配置）"

CFG=/var/lib/turnout/mihomo/config.yaml
if [ ! -f "$CFG" ]; then
  bad "渲染配置不存在：$CFG"
else
  ok "渲染配置存在：$CFG"

  if [ -n "$EG_IF" ]; then
    # `proxies: []` means no subscription is configured. That is a real gap
    # (nothing can be proxied) but it is NOT the bug this check hunts: with
    # zero proxies there is nothing to bind, and reporting "no proxy binds
    # <iface>" would send the operator looking at the renderer.
    if grep -qE '^proxies: \[\]' "$CFG" 2>/dev/null; then
      skip "配置里没有 proxy（subscriptions 为空）—— 补齐订阅后才能验证出口绑定"
    else
      bound=$(grep -c "interface-name: $EG_IF" "$CFG" 2>/dev/null || echo 0)
      if [ "$bound" -gt 0 ] 2>/dev/null; then
        ok "出口绑定：$bound 个 proxy 绑到 $EG_IF"
      else
        bad "没有任何 proxy 绑定 interface-name: $EG_IF —— 出墙流量会跟默认路由进防火墙"
      fi
    fi
  fi

  # Only the top-level `rules:` block: `sub-rules:` (per-terminal mode) is
  # rendered after it and every sub-rule ends in its own MATCH,<pool>, so a
  # whole-file grep picked up `MATCH,ai-pool` and failed a correct config.
  last_rule=$(awk '/^rules:/{on=1; next} /^[^[:space:]-]/{on=0} on' "$CFG" 2>/dev/null \
    | grep -E '^\s*- (MATCH|GEOIP|RULE-SET|IP-CIDR|DOMAIN)' | tail -1)
  case "$last_rule" in
    *MATCH,DIRECT*) ok "规则兜底是 MATCH,DIRECT（未命中白名单的流量交还防火墙）" ;;
    *MATCH*)        bad "规则兜底不是 DIRECT：$last_rule —— 白名单模式应以 MATCH,DIRECT 结束" ;;
    *)              skip "未能从配置中定位最后一条规则（格式可能已变）" ;;
  esac
fi

# ── summary ─────────────────────────────────────────────────────────────────

head_ "结果"
printf '  PASS %d   FAIL %d   SKIP %d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
  printf '\n  失败项：\n'
  for n in "${FAILED_NAMES[@]}"; do printf '    - %s\n' "$n"; done
fi

cat <<'MANUAL'

────────────────────────────────────────────────────────────────
以下三项只能在防火墙侧确认，脚本无法验证（请不要当作已验证）：

  1. PBR 规则的 source-address 与本机 client_subnet 一致，
     且规则限定了「原入接口」——否则旁挂机回程会被二次引流成环。
  2. IP-Link 的 destination 等于 watchdog.liveness_ip，
     并已放行 local→untrust 的探测报文（否则永远 Up 不起来）。
  3. 办公网内网系统没有基于源 IP 的 ACL。
     方案 B 的回程会做 NAT，源 IP 变成旁挂机地址；若内网依赖源 IP，
     需要改用方案 A（见 PLAN.md P2）。

切换演练（人工，每次 5 分钟）：
  · 防火墙上手动切回直连 → 确认全网恢复、无残留
  · 关掉本机（或 systemctl stop turnout-*）→ 确认 IP-Link Down → 流量回落
  · 恢复 → 确认切回后服务正常
────────────────────────────────────────────────────────────────
MANUAL

exit "$FAIL"
