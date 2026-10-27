# Turnout · 道岔网关

**旁挂在办公网防火墙上，给每一股流判定走哪条道的一台 Linux 设备。**

终端 → 防火墙（PBR 引流）→ 本设备判定 → 该翻墙的走海外池 / 不该翻墙的原样交回防火墙。
DNS 同样经本设备处理。零客户端、零终端配置。

派生自 [leap-gateway / Interchange](../leap-gateway)（飞连转发节点侧车），
复用其控制面与 mihomo 数据面，替换入向模型并新增自检降级能力。

---

## 1. 和上游的本质差异

| 维度 | Interchange（上游） | turnout-gateway（本项目） |
|---|---|---|
| 部署位置 | 飞连转发节点，串在 VPN 出口 | 旁挂在防火墙边，靠 PBR 引流 |
| 入向 | `tun0` + fwmark 策略路由 | 面向防火墙的物理口 + TPROXY |
| 入向源地址 | 飞连客户端池 `10.8.x.0/24` | 办公网段（如 `10.1.0.0/16`） |
| 判定后"不需要翻墙"的动作 | 从本机出口网卡直接出 | **交回防火墙**，由防火墙正常转发 |
| 出向"翻墙" | 机场节点池 | 机场节点池（不变） |
| 失效处理 | 飞书告警 + 人工 | + 本机 watchdog 主动摘除探活地址，防火墙自动回切 |

一句话：**控制面几乎原样搬，数据面的"两条腿"要重新定义——一条出墙，一条回防火墙。**

---

## 2. 拓扑与数据流

```
                        办公室终端
                             │
                             ▼
                    ┌─────────────────┐
                    │  华为 USG6000E   │
                    │  PBR: 源=办公网段 │
                    │  原入接口=LAN    │
                    └────┬───────▲────┘
            引流(命中PBR) │       │ 回程(不命中PBR)
                         ▼       │
               ┌─────────────────┴──────────────┐
               │      turnout-gateway (Linux)      │
               │                                  │
               │  ens-ly ──┐                      │
               │           ├─► TPROXY:7893        │
               │  ens-ly ◄─┘      │               │
               │                  ▼               │
               │           mihomo 判定             │
               │          ╱          ╲            │
               │    whitelist命中   其余命中       │
               │        │              │          │
               │        ▼              ▼          │
               │   海外池出墙      从 ens-fw 交回   │
               │   (ens-out)       防火墙          │
               └──────────────────────────────────┘
                         │                    │
                         ▼                    ▼
                    海外站点            国内站点 / 内网
```

**关键路由约束（必读）**

已定方案 B（TPROXY 全量 + mihomo DIRECT 出站，见 PLAN.md P2）：

1. **默认路由指向防火墙那一侧的 next-hop**（`node.return.gateway_ip`）。
   这是回程的全部机制：mihomo 判定为 DIRECT 的流量从其出站走本机默认路由，
   下一跳即防火墙 —— 流量因此交还，由防火墙正常转发。
2. **回程不会造成环路**，有两个独立原因：
   - 回程流量是从本机重新发起的（源地址是本机地址），
     不匹配防火墙 PBR 的 `source-address = 办公网段`；
   - 你已确认防火墙 PBR 指定了原入接口，与本机回程出口不共用。

   这正是方案 B 不需要单独回程物理口的原因。
3. 出墙流量由 mihomo 从 `node.egress_iface` 主动发起，**出站绑定该接口**，
   因此不经过默认路由（否则会被送进防火墙绕一圈再出去）。
4. TPROXY 的 `ip rule fwmark 0x44 lookup 101` 只对本机"收到"的包生效；
   回程是 mihomo 主动发出的包，不打 fwmark。但仍需在 nft 侧确认
   **FORWARD 链没有挂 TPROXY**。
5. 入向源 IP 由 TPROXY 保留（这正是上游 `inbounds.go` 弃用 TUN 的原因），
   所以 per-terminal 成立——"用户身份用源 IP 够用"这条前提满足。
   注意区分：**入向**源 IP 保留（用于识别终端），**回程**源 IP 会被 NAT
   （用于交还防火墙），两者不是一回事。

---

## 3. 判定逻辑（沿用上游，不改）

白名单模式，规则的顺序与语义与 Interchange 完全一致（见 `internal/mihomo/rules.go` 上游实现）：

```
1. IP-CIDR,私网段          → DIRECT   （交回防火墙）
2. RULE-SET,geosite-cn     → DIRECT
3. RULE-SET,geoip-cn       → DIRECT,no-resolve
4. [白名单 geosite 标签]    → out / perterm
5. [白名单 DOMAIN-SUFFIX]   → out / perterm
6. [白名单 geoip 标签]      → out,no-resolve
7. [白名单 IP-CIDR]         → out,no-resolve
8. MATCH                   → DIRECT   ← 兜底：无法分类的一律交回防火墙
```

第 8 行的存在，让"纯 IP 目标 / QUIC / 非 HTTP 私有协议"**自动**落到直连，
不需要任何额外处理。这就是你问的那条：能与现有保持一致，且是天然一致。

**能分类的范围**（嗅探器 `sniffer.go`，同样沿用）：
- TLS SNI：443 / 8443
- HTTP Host：80 / 8080-8880
- QUIC ALPN：443
- `parse-pure-ip: true`：目标是纯 IP 也照嗅
- `override-destination: true`：嗅出域名后改写目标，用于 geosite 匹配

**盲区**：端口不在上述列表、且非 TLS/HTTP/QUIC 的私有协议 → 走第 8 行直连。
对白名单模型这是正确行为。

**DNS 角色**：沿用上游的 `redir-host`（真实 IP，不用 fake-ip）+ SNI 嗅探。
理由是上游 2026-07-06 从 fake-ip 切回 redir-host 的那两个故障（内网域被假 IP 误伤、
机场节点域名解析失败）在办公环境只会更严重——办公网里 NAS、打印机、监控、
内网业务系统大量靠纯 IP 或内网域名直连，fake-ip-filter 会变成一个无底洞。

> 暂不处理 DoH/ECH 场景（按你的要求）。届时终端自带 DoH 会让嗅探失效，
> 这类流量落到第 8 行直连——**表现为"翻墙不生效"而不是"断网"**，
> 属于可接受的降级方向。后续如需收紧，再考虑劫持 53 或阻断 853。

---

## 4. 出墙出口（沿用上游）

机场订阅 + NodeScorer 双窗 EWMA 打分 + 池决策 + per-terminal（一个终端一个出口 IP，
避免 Cloudflare/OpenAI 风控）+ 飞书告警。这部分代码不动。

规模维持现状（少量用户试用，实测 50 稳定 / 150 降级，瓶颈是机场带宽）。

---

## 5. 失效与回切

**手动回切是你的兜底，自动回切靠 IP-Link。** 华为 USG6000E 的约束：

- 能联动 `policy-based-route` 的只有 **IP-Link**；它**只支持 `icmp` 和 `arp`** 两种探测模式，
  **没有 HTTP/TCP**。
- 智能选路的 Health Check 支持 ICMP/TCP/HTTP/DNS/UDP，但它属于智能选路的选路池，
  **不能绑定经典 PBR**。

因此自动回切只能用 ICMP/ARP 探活。而 ICMP 探活有个致命缺口：

> **它探的是内核，不是数据面。** mihomo 崩溃、nft 规则被刷掉、出口池全挂——
> 这三种情况下机器照样秒回 ICMP，防火墙认为一切正常，继续把整个办公网的
> 流量灌进黑洞。手动切回的前提是"你知道它挂了"，而这时你不知道。

**解法：把探测信号的准确性做成本机自己的责任。** `turnout-gateway` 进程内跑一个
watchdog goroutine（不是独立单元——它要读 `assert.go` 的断言状态和 NodeScorer 的
池状态，两者都活在控制面进程里）：

```
watchdog 每 N 秒自检（默认 10s）：
  a. mihomo 进程存活 + clash-api /version 可达
  b. 数据面规则在位（消费 assert.go 的既有状态，不重复实现）
  c. 出口池里至少一个节点健康（复用 NodeScorer 的状态）
  d. 端到端探测：经代理实取一个 URL（默认关闭，会产生真实流量）
  e. DNS 解析：经本机监听解析一个白名单域名（默认开启）
     —— 其余检查全绿时解析仍可能全挂；2026-10-24 的故障正是这样

全部通过 → 探活地址在位，应答 ICMP → 防火墙 IP-Link Up   → PBR 生效
任一失败 → 摘掉探活地址             → 防火墙 IP-Link Down → 回落直连
```

判定不是单次采样：连续失败 `fail_threshold` 次（默认 3）才判不健康，
连续通过 `recover_threshold` 次（默认 3）才恢复——与防火墙 IP-Link 自身的
revertive 语义对齐。`assert.go` 可能在我们下一次自检前就修好了瞬时的规则丢失。

这样把一个 L3 的哑探针，变成了反映数据面真实健康度的信号。
`arp` 模式更可靠（同网段直连、不受对端 ICMP 策略影响），旁挂机与防火墙同 VLAN 时优先用；
注意 ARP 模式要求探活地址绑在**物理口**而非 `lo`（见配置项 `liveness_iface`）。

### 探活地址：部署时必填，无默认值

`liveness_ip` 是刻意不给默认值的。它是本机与防火墙之间**唯一的健康信号通道**，
配错会静默故障：

- 漏填 → watchdog 摘了个不存在的地址，防火墙毫无感知，继续灌黑洞
- 填成 `node.ingress_ip` → 摘下地址时 **SSH 和 API 一起失联**，你连上去排查的路都没了
- 填成网段内别的设备在用的地址 → 冲突

`install.sh` 的 precheck 会拒绝空值，并要求它与 `node.ingress_ip` 不同。

### 降级动作默认关闭（`auto_failover: false`）

配置里区分了"**报信**"和"**动作**"两件事：

| `auto_failover` | 判定不健康时 |
|---|---|
| `false`（默认） | 只推飞书告警（含失败的具体检查项），探活地址保持应答，防火墙不动作 |
| `true` | 摘掉探活地址 → IP-Link Down → PBR 失效 → 流量自动回落直连 |

**建议上线初期保持 `false`，只告警不动作，观察一到两周真实故障率。**
试用期用户少，手动切回足够；自动摘地址在"数据面半死"时会给出假的安全感
（探针说健康、实际黑洞），反而不如没有。确认故障模式可预期后再置 `true`——
这是配置项而非代码分支，切换不需要重新部署。

**配套注意**（防火墙侧，你实现）：
- IP-Link 探测包从 `local` 区发出，安全策略必须放行，否则永远 Up 不起来。
- 探测包与回包的路由双向可达。
- 默认约 3 个周期（15s）判 Down，连续 3 次响应才判 Up；开启 revertive delay 更慢。
- 观察命令：`display ip-link status` / `display ip-link track`。

**建议的推进节奏**：先只配 IP-Link 做**告警**（Down 时经现有飞书通路推一条），
跑一段时间观察真实故障率，再决定是否启用 watchdog 的自动摘地址。少量用户试用阶段，
手动切回足够；ICMP 自动回切在"数据面半死"时会给出假的安全感，反而不如没有。

---

## 6. 配置模型

见 `configs/gateway.example.yaml`。相对上游的 schema 变化：

| 上游字段 | 新字段 | 说明 |
|---|---|---|
| `node.client_subnet` | 保留 | 改为办公网段 |
| `node.tun0_gateway_ip` | `node.ingress_ip` | DNS 监听地址绑在它上面 |
| （无） | `node.ingress_iface` | 面向防火墙的网卡名 |
| `node.egress_iface` | 保留 | 出去到机场节点的网卡 |
| （无） | `node.return.*` | **新增**：回程下一跳（指向防火墙） |
| `data_plane.tproxy_port` | 保留 | 必需 |
| `data_plane.tun.enabled` | 保留（`false`） | 上游也是靠 TPROXY，TUN 块只是占位 |
| （无） | `watchdog.*` | **新增**：自检间隔、检查项、探活地址（必填）、降级开关 |

`subscriptions:` 块语义不变。

> ⚠️ 上游 `CLAUDE.md` 的硬规则在本项目同样有效：
> **任何情况下不得增删改重排节点订阅**。从上游同步配置 schema 时，
> 必须把目标节点的 `subscriptions:` 块原样拼接回去。

---

## 7. 运行观测（turnout-healthwatch）

随包部署的采样器，每 60s 把系统状态写成一行 JSON，落到
`/var/lib/turnout/health/health-YYYY-MM-DD.jsonl`（保留 30 天）。它独立于
控制面进程：turnout-gateway 重启期间照常记录 —— 重启正是最容易出问题的
时刻（见 2026-10-24 的两次启动事故）。

每条记录包含：

- `/healthz` 的数据面断言结论 + 失败项
- 池大小 / K / tier1 / 最近评分与刷新时间
- 池内每个节点的 RTT、抖动、fail_rate、探测次数、活动连接
- 本区间内的换池次数 + 5m/1h/24h 窗口（换池频率优化的主要信号）
- 渲染配置的 mtime/大小、fallback 组数、per-terminal 规则数
  （能一眼看出“1027 组”这类退化）
- 日志增量：热重载次数/失败/耗时、评分轮次、暖机跳过、warn/error、DNS 解析失败
- 重载归因：`routing_changed` / `named_changed` / `named_deferred` / `probing_changed`，
  直接区分“路由换人 / 分类池换人 / 探测集变化”
- 探测终端的默认出口与**分类池（AI）出口**：主备节点、RTT p50/p95、fail_rate；
  `--summary` 汇总“主备同订阅比例”（跨订阅 secondary 上线前为 99.6%，越低说明
  单一入口故障时 fallback 越能接住）
- 经网关 resolver 解析一个白名单域名的真实时延（按 `preload_domains` 轮换）
- 直连 `1.1.1.1:853/443`、`8.8.8.8:443` 的连通性
  （2026-10-24 的故障正是这条直接路径被阻断）
- 经探测终端的出口分组访问 `https://www.youtube.com` 的端到端时延
- mihomo / gateway 的 RSS、load1、可用内存、磁盘

配置一个真实终端作为探测目标（可选）：

```bash
echo 'HEALTHWATCH_PROBE_IP=192.168.13.2' | sudo tee /etc/turnout/healthwatch.env
sudo systemctl restart turnout-healthwatch
```

查看最近 24h 汇总：

```bash
sudo turnout-healthwatch --summary --summary-hours 24
```

---

## 8. 文档

- [`PLAN.md`](PLAN.md) — 基于 Interchange 的修改开发计划（分阶段、可验证）
- [`CHANGES-FROM-UPSTREAM.md`](CHANGES-FROM-UPSTREAM.md) — 逐包/逐文件的保留、修改、删除、新增清单
- `configs/gateway.example.yaml` — 注释版配置模板
