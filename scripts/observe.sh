#!/usr/bin/env bash
# observe.sh — one-shot, staged view of a bypass node's traffic path.
#
# Runs ON the node (needs iptables + the local API), piped over ssh:
#
#   ssh ops@<host> 'sudo -n bash -s' < scripts/observe.sh
#   make observe NODE=ops@<host>
#
# WHY A LADDER AND NOT A DUMP
#
# Every failure this deployment has looks identical from the outside: "the
# site does not open". Which of five stages broke decides who fixes it —
# the firewall team, this node's config, or the airport subscription. So the
# output is ordered as the packet's own journey and each stage says PASS /
# FAIL / IDLE on its own:
#
#   1  divert     firewall is sending the segment here      (PREROUTING jump)
#   2  intercept  the kernel hands packets to mihomo        (TPROXY target)
#   3  classify   mihomo sees them and applies a rule       (/connections)
#   4  egress     the chosen chain actually reaches a node  (pool + active)
#   5  return     DIRECT verdicts go back to the firewall   (default route)
#
# IDLE is not a failure: with no client traffic stages 1-3 are legitimately
# quiet. It becomes a failure only if you are generating traffic right now —
# which is why the script also prints a delta over SAMPLE_SECONDS and tells
# you to hold a request open while it samples.
#
# Env:
#   SAMPLE_SECONDS   counter sampling window (default 6)
#   API_PORT         control-plane port (default 18080)
#   CLASH_PORT       mihomo external controller port (default 9090)
#   EXPECT_SRC       a terminal IP you expect to see (optional; stages 3/4
#                    then report whether that source showed up)

set -uo pipefail

SAMPLE_SECONDS="${SAMPLE_SECONDS:-6}"
API_PORT="${API_PORT:-18080}"
CLASH_PORT="${CLASH_PORT:-9090}"
EXPECT_SRC="${EXPECT_SRC:-}"
API="http://127.0.0.1:${API_PORT}"
CLASH="http://127.0.0.1:${CLASH_PORT}"

PASS=0; FAIL=0; IDLE=0
pass() { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m  %s\n' "$*"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m  %s\n' "$*"; }
idle() { IDLE=$((IDLE+1)); printf '  \033[33mIDLE\033[0m  %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$*"; }
fix() { printf '        \033[36m→ %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "must run as root (sudo)" >&2; exit 2; }

# ── counters ────────────────────────────────────────────────────────────────
# One line per iptables rule that matters, as absolute packet counts.
# `-x` gives exact numbers; parsing -v text would round KB and hide slow flows.

counters() {
  # Parse by column, not by text. `iptables -L -v -x` columns are
  #   pkts bytes target prot opt in out source destination [extra]
  # and prot is printed NUMERICALLY (6 / 17), so matching on the word
  # "tcp" never hits the TPROXY tcp rule — tproxy_tcp read 0 from the day
  # this script shipped and all TCP was misfiled as "other".
  { iptables -t mangle -L PREROUTING -v -n -x 2>/dev/null | awk '
      $3=="TURNOUT_TPROXY" {print "jump", $1}
      $3=="DROP" && /dpt:18080/ {print "api_drop", $1}'
    iptables -t mangle -L TURNOUT_TPROXY -v -n -x 2>/dev/null | awk '
      $3=="RETURN" && /dst-type LOCAL/ {print "local_return", $1}
      $3=="RETURN" && $4=="6" && /dpt:53/ {print "dns_tcp_return", $1}
      $3=="TPROXY" && $4=="6"  {print "tproxy_tcp", $1}
      $3=="TPROXY" && $4=="17" {print "tproxy_udp", $1}'
    iptables -t nat -L TURNOUT_DNS -v -n -x 2>/dev/null | awk '
      $3=="DNAT" && $4=="17" {print "dns_udp", $1}
      $3=="DNAT" && $4=="6"  {print "dns_tcp", $1}'
  } | sort
}

snap1=$(counters)
sleep "$SAMPLE_SECONDS"
snap2=$(counters)

delta() { # delta NAME → count change over the window
  local a b
  a=$(printf '%s\n' "$snap1" | awk -v k="$1" '$1==k{print $2}')
  b=$(printf '%s\n' "$snap2" | awk -v k="$1" '$1==k{print $2}')
  echo $(( ${b:-0} - ${a:-0} ))
}

# ── 0. identity ─────────────────────────────────────────────────────────────

head_ "0. 节点"
VER=$(curl -s --max-time 5 "$API/api/proxies/active" 2>/dev/null)
if [ -n "$VER" ]; then
  printf '%s' "$VER" | python3 -c '
import json,sys
d=json.load(sys.stdin)
t=d.get("turnout",{}) ; n=d.get("node",{})
print("        version  %s" % t.get("gateway_version","?"))
print("        services %s" % t.get("services",{}))
print("        cluster  client_subnet=%s  egress=%s" % (n.get("client_subnet"), n.get("egress_iface")))
' 2>/dev/null
  pass "控制面 API 可用"
else
  fail "控制面 API 不可达（$API）—— 后面几级都不可信"
  fix "systemctl status turnout-gateway; journalctl -u turnout-gateway -n 50"
fi

HZ=$(curl -s --max-time 5 "$API/healthz" 2>/dev/null)
if [ -n "$HZ" ]; then
  printf '%s' "$HZ" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for c in d.get("checks") or []:
    mark = "ok " if c.get("ok") else "BAD"
    print("        %s %s — %s" % (mark, c["name"], c.get("detail","")))
' 2>/dev/null
  case "$HZ" in *'"ok":true'*) pass "/healthz 数据面断言通过" ;; *) fail "/healthz 断言未通过" ;; esac
fi

# ── 1-2. kernel path ────────────────────────────────────────────────────────

head_ "1-2. 内核拦截（${SAMPLE_SECONDS}s 采样）"

JUMP=$(delta jump)
TCP=$(delta tproxy_tcp)
UDP=$(delta tproxy_udp)
RET=$(delta local_return)

jump_rule=$(iptables -t mangle -S PREROUTING 2>/dev/null | grep 'TURNOUT_TPROXY')
printf '        规则  %s\n' "${jump_rule:-<none>}"
printf '        窗口  jump=+%s  tproxy_tcp=+%s  tproxy_udp=+%s  local_return=+%s\n' "$JUMP" "$TCP" "$UDP" "$RET"

if [ -z "$jump_rule" ]; then
  fail "PREROUTING 没有跳转规则 —— 没有任何流量会进本节点"
  fix "systemctl restart turnout-nft（或 make redeploy 让 iproute.sh 重装规则）"
elif [ "$JUMP" -eq 0 ]; then
  idle "窗口内没有包进入跳转 —— 防火墙此刻没在导流，或没有终端在访问外网"
  fix "保持一个页面在刷新，再跑一次；仍为 0 就是防火墙侧 PBR 没命中"
else
  # The jump counter also counts traffic addressed to this box — the
  # operator's own SSH and the console's API polling come from the same
  # client_subnet and match the jump, then RETURN on dst-type LOCAL. So
  # "jump>0, tproxy=0" is NOT automatically a fault; it is a fault only
  # when packets were headed OUT and still missed TPROXY. Compare the two
  # counters before grading.
  # Packets that fall through the chain without TPROXY or a LOCAL return
  # are, by construction, UDP/TCP 53 (handed to the nat DNS hijack) or
  # non-TCP/UDP (ICMP). They are expected, so they are reported as a
  # breakdown, never graded as a failure. The nat DNAT counter only sees
  # the first packet of each flow, so the two numbers do not reconcile.
  DNSRET=$(delta dns_tcp_return)
  OTHER=$((JUMP - RET - TCP - UDP - DNSRET))
  [ "$OTHER" -lt 0 ] && OTHER=0
  info "细分  本机=$RET  TPROXY=$((TCP + UDP))  DNS/ICMP 等=$OTHER"
  if [ $((TCP + UDP)) -gt 0 ]; then
    pass "TPROXY 接住 $((TCP + UDP)) 包（tcp=$TCP udp=$UDP）"
  elif [ "$OTHER" -gt 0 ]; then
    idle "窗口内只有 DNS / ICMP 经过（交给 2b 级处理），没有 TCP/UDP 业务流量"
  else
    idle "窗口内只有发往本机的流量（jump=$JUMP，全部 LOCAL 返回）—— 尚无被引流的外网流量"
    fix "这是 SSH / 控制台轮询本身。保持一个外部页面在访问，再采样一次"
  fi
fi

fwmark=$(ip rule show | grep -c 'fwmark 0x44')
t101=$(ip route show table 101 | grep -c '^local ')
if [ "$fwmark" -ge 1 ] && [ "$t101" -ge 1 ]; then
  pass "fwmark 0x44 → table 101 → local 投递在位"
else
  fail "策略路由缺失（rule=$fwmark table101=$t101）—— 被 TPROXY 标记的包会走普通路由"
  fix "systemctl restart turnout-nft"
fi

# ── 2b. DNS hijack ──────────────────────────────────────────────────────────
# Terminals keep their own resolvers; the firewall diverts those queries
# here and the nat chain hands them to mihomo. If this stage is broken the
# symptom is "nothing resolves" on every diverted terminal — worse than
# any routing fault, so it gets its own stage.

head_ "2b. DNS 劫持（终端自带的 223.5.5.5 / 119.29.29.29 等）"
DNSU=$(delta dns_udp); DNST=$(delta dns_tcp)
hijack_flag=$(grep -m1 'TURNOUT_DNS_HIJACK' /etc/turnout/env 2>/dev/null | sed 's/.*=//' | tr -d '"')
dns_jump=$(iptables -t nat -S PREROUTING 2>/dev/null | grep 'TURNOUT_DNS')
printf '        规则  %s\n' "${dns_jump:-<none>}"
printf '        窗口  dnat_udp=+%s  dnat_tcp=+%s\n' "$DNSU" "$DNST"
if [ "${hijack_flag:-1}" != "1" ]; then
  idle "DNS 劫持已关闭（data_plane.dns.hijack=false）—— 被导流的终端 DNS 会在防火墙和本机之间成环"
elif [ -z "$dns_jump" ]; then
  fail "DNS 劫持已开启但 nat PREROUTING 没有跳转 —— 被导流终端会完全无法解析"
  fix "systemctl restart turnout-nft（iproute.sh 会重装 TURNOUT_DNS）"
elif [ $((DNSU + DNST)) -gt 0 ]; then
  pass "劫持了 $((DNSU + DNST)) 个 DNS 查询（udp=$DNSU tcp=$DNST）"
else
  idle "窗口内没有被导流的 DNS 查询"
  fix "终端执行 dig @223.5.5.5 www.google.com 再采样；仍为 0 说明防火墙没导 53 端口（不影响分流，SNI 嗅探兜底）"
fi

# ── 3. classification ───────────────────────────────────────────────────────

head_ "3. mihomo 判定"

CONNS=$(curl -s --max-time 5 "$CLASH/connections" 2>/dev/null)
if [ -z "$CONNS" ]; then
  fail "clash API $CLASH 无响应"
  fix "systemctl status turnout-mihomo"
else
  printf '%s' "$CONNS" | EXPECT_SRC="$EXPECT_SRC" python3 -c '
import json,sys,os,collections
d=json.load(sys.stdin)
cs=d.get("connections") or []
exp=os.environ.get("EXPECT_SRC","")
by_type=collections.Counter()
by_src=collections.Counter()
by_chain=collections.Counter()
for c in cs:
    m=c.get("metadata",{})
    by_type[m.get("type","?")]+=1
    src=m.get("sourceIP","?")
    by_src[src]+=1
    chain=" > ".join(reversed(c.get("chains") or [])) or "-"
    by_chain[chain]+=1
print("        活跃连接 %d" % len(cs))
if by_type: print("        type     " + "  ".join("%s=%d"%(k,v) for k,v in by_type.most_common()))
if by_src:  print("        来源     " + "  ".join("%s=%d"%(k,v) for k,v in by_src.most_common(6)))
if by_chain:print("        出口链   " + "  ".join("%s(%d)"%(k,v) for k,v in by_chain.most_common(4)))
if exp:
    print("        期望源 %s  出现 %s" % (exp, "是" if exp in by_src else "否"))
' 2>/dev/null
  tproxy=$(printf '%s' "$CONNS" | python3 -c 'import json,sys; print(sum(1 for c in (json.load(sys.stdin).get("connections") or []) if str(c.get("metadata",{}).get("type","")).lower()=="tproxy"))' 2>/dev/null)
  if [ "${tproxy:-0}" -gt 0 ]; then
    pass "mihomo 持有 $tproxy 条 TPROXY 连接"
  else
    idle "没有 TPROXY 连接（空闲，或客户端流量未到达）"
    fix "若此刻正在访问外网，回到第 1-2 级检查计数"
  fi
fi

# per-terminal 是否真的生效。enumerateHosts caps at 1024 hosts and RETURNS
# NIL past it, which silently disables per-terminal grouping — the config
# still says per_terminal: true and nothing in the UI says otherwise.
# /16 (65534 hosts) hits this; /22 (1022) does not. Caught 2026-10-22.
if [ -f /var/lib/turnout/mihomo/config.yaml ]; then
  pt_cfg=$(grep -c 'per_terminal: true' /etc/turnout/gateway.yaml 2>/dev/null)
  # Host mode emits SRC-IP-CIDR, bucket mode (subnets over 1024 hosts)
  # emits SRC-IP-SUFFIX. Counting only the former reported every bucketed
  # deployment as "per-terminal disabled".
  pt_rules=$(grep -cE 'SRC-IP-(CIDR|SUFFIX)' /var/lib/turnout/mihomo/config.yaml 2>/dev/null)
  if [ "${pt_cfg:-0}" -gt 0 ] && [ "${pt_rules:-0}" -eq 0 ]; then
    fail "per_terminal 已开启但没有渲染出任何 per-terminal 分组 —— 客户端网段过大，所有终端共用同一出口"
    fix "检查是否有一台都渲染不出来：make nodes NODE=... 看池；规则数应为 1024"
  elif [ "${pt_rules:-0}" -gt 0 ]; then
    pass "per-terminal 分组已渲染（$pt_rules 条 SRC-IP-(CIDR|SUFFIX) 规则）"
  fi
fi

# 判定结果分布：最容易出问题的一层 —— 域名没进白名单就落到 MATCH,DIRECT
if [ -n "$CONNS" ]; then
  printf '%s' "$CONNS" | python3 -c '
import json,sys,collections
cs=json.load(sys.stdin).get("connections") or []
r=collections.Counter()
for c in cs:
    r[(c.get("rule") or "-") + " -> " + "→".join((c.get("chains") or ["-"])[:1])]+=1
for k,v in r.most_common(8): print("        %-38s %d" % (k,v))
' 2>/dev/null
fi

# ── 4. egress ───────────────────────────────────────────────────────────────

head_ "4. 出口池"

ST=$(curl -s --max-time 5 "$API/api/status" 2>/dev/null)
if [ -n "$ST" ]; then
  printf '%s' "$ST" | python3 -c '
import json,sys
d=json.load(sys.stdin)
print("        pool eligible=%s size=%s total=%s nodes=%s" % (
  d.get("pool_eligible"), d.get("pool_size"), d.get("pool_total"), d.get("node_count")))
' 2>/dev/null
  el=$(printf '%s' "$ST" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("pool_eligible",0))' 2>/dev/null)
  if [ "${el:-0}" -gt 0 ]; then pass "池里有合格节点"; else
    fail "池里没有合格节点 —— 命中白名单的流量无处可去"
    fix "make nodes NODE=... 看打分；订阅是否过期见订阅页"
  fi
fi

if [ -n "$VER" ]; then
  printf '%s' "$VER" | python3 -c '
import json,sys
d=json.load(sys.stdin); ap=d.get("active_proxy") or {}
for p in ap.get("pools") or []:
    e=p.get("egress") or {}
    print("        %s: now=%s egress=%s %s" % (p.get("tag"), ap.get("now") or "-", e.get("ip","-"), e.get("country","")))
' 2>/dev/null
fi

# ── 5. return path ──────────────────────────────────────────────────────────

head_ "5. 回程"

rt=$(ip route show default | head -1)
gw=$(grep -m1 'TURNOUT_RETURN_GATEWAY' /etc/turnout/env 2>/dev/null | cut -d'"' -f2)
printf '        默认路由 %s\n' "$rt"
if [ -n "$gw" ] && printf '%s' "$rt" | grep -q "via $gw"; then
  pass "默认路由指向防火墙 ($gw) —— DIRECT 判定会交还防火墙"
else
  fail "默认路由不指向 return.gateway_ip=${gw:-<unset>}"
  fix "systemctl restart turnout-return-route（iproute.sh 不管这一层）"
fi

# ── 6. recent alerts ────────────────────────────────────────────────────────

head_ "6. 近期告警（本机日志，未外发）"
if [ -f /var/lib/turnout/notifications.log ]; then
  tail -5 /var/lib/turnout/notifications.log | python3 -c '
import json,sys
for line in sys.stdin:
    line=line.strip()
    if not line: continue
    try: e=json.loads(line)
    except Exception: continue
    print("        %s  [%s] %s" % (e.get("at","")[:19], e.get("severity","?"), e.get("subject","")))
' 2>/dev/null
else
  info "无通知日志"
fi

# ── summary ─────────────────────────────────────────────────────────────────

head_ "结果"
printf '  PASS %d   FAIL %d   IDLE %d\n' "$PASS" "$FAIL" "$IDLE"
if [ "$FAIL" -gt 0 ]; then
  printf '\n  按上面的顺序逐级修：第 1-2 级是防火墙/内核，第 3 级是本机配置，第 4 级是订阅，第 5 级是回程路由。\n'
fi
exit "$FAIL"
