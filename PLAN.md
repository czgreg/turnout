# 开发计划 —— 基于 Interchange (leap-gateway) 的改造

目标：把飞连转发节点侧车，改造为防火墙旁挂的引流判定网关。

原则：**能不动就不动。** 上游的控制面（订阅、打分、池、API、控制台、告警）
在旁挂场景下语义完全成立，一行不用改。所有改动集中在**入向**（tun0 → 物理口）、
**回程**（本地出网 → 交还防火墙）、以及**新增的自检降级**三处。

---

## P0 — 立项目与建立基线

**目标**：拿到一份可编译、可测试、行为与上游一致的代码，并锁住"改造前"的基线。

1. 复制上游仓库（保留 git 历史，便于后续 `git log` 追溯每个决策的来由）：
   ```
   cp -a ../leap-gateway/. ./ && rm -rf ./gateway ./build
   git remote rename origin upstream
   git remote set-url upstream <upstream-url>
   ```
2. 重命名模块与标识符（一次全局替换，之后不改）：
   - `go.mod`：`github.com/leap-gateway/leap-gateway` → `github.com/turnout-gateway/turnout-gateway`
   - Go 源码 import 路径同步
   - 磁盘标识：`/etc/leap/` → `/etc/turnout/`、`/var/lib/leap/` → `/var/lib/turnout/`
   - systemd 单元：`leap-gateway/-mihomo/-nft` → `turnout-gateway/-mihomo/-nft`
   - iptables 链名：`LEAP_TPROXY` → `TURNOUT_TPROXY`
   > 磁盘标识**不保留兼容层**。本项目是新部署，不是原地升级，留着双份命名
   > 只会在排查时浪费时间。
3. 建立基线：
   - `make build` 通过
   - `go test ./...` 全绿，记录用例数
   - `git tag baseline-upstream` —— 之后任何"和上游行为不一致"的疑问都以它为参照
4. 把上游 `CLAUDE.md` 的硬规则原样搬进新仓库的 `CLAUDE.md`：
   **⛔ 永不动节点订阅**。这条在新项目同样有效，且同样重要。

**交付**：仓库可构建、测试全绿、打上基线 tag。
**验证**：`make build && go test ./...` 全绿；`git log --oneline | head` 能看到上游历史。

---

## P1 — 入向改造：tun0 → 物理口

**目标**：让设备从面向防火墙的物理网卡收流量，而不是从飞连 tun0。

| 文件 | 改动 |
|---|---|
| `internal/config/config.go` | `Node.Tun0GatewayIP` → `Node.IngressIP`；新增 `IngressIface` |
| `internal/mihomo/dns.go` | DNS `listen` 改绑 `IngressIP` |
| `internal/mihomo/inbounds.go` | TUN 块判定条件从 `Tun0GatewayIP` 改为 `IngressIP`（保持 `enabled: false`） |
| `deploy/node/iproute.sh` | `LEAP_TUN0_IFACE` → `BYPASS_INGRESS_IFACE`；PREROUTING 匹配 `-i $INGRESS_IFACE -s $CLIENT_SUBNET` |
| `deploy/node/nft.conf.tmpl` | 入向网卡名、源网段、API 防护规则里的 `10.8.0.0/16` 硬编码 |
| `deploy/node/install.sh` | `precheck()` 里的 feilian-tun / tun0 检查项全部删除，换成旁挂机检查项 |
| `cmd/render-mihomo/main.go` | 渲染参数同步 |

**precheck 要换成的新检查项**：
- `IngressIface` 存在且 up
- `IngressIP` 已配置在该网卡上
- `net.ipv4.ip_forward = 1`
- `net.ipv4.conf.all.rp_filter ∈ {0, 2}`（fwmark 策略路由需要 loose 模式）
- 内核支持 `xt_TPROXY`
- `InressIP:53` 与 API 端口空闲
- `EgressIface` 可达互联网

**交付**：设备能接收办公网段流量并完成分流判定。
**验证**：在旁挂机上 `curl` 一个测试域名，`mihomo` 的 `/connections` 里能看到**真实客户端源 IP**
（若显示 `198.18.0.0` 说明走到了 TUN 而非 TPROXY，per-terminal 会失效）。

> ⚠️ 上游 `inbounds.go:23-30` 有一条明确记录：TUN 的两种 stack 都会把客户端源 IP
> 塌缩成 `198.18.0.0`，per-terminal 必须走 TPROXY。这条约束在旁挂场景下同样成立。

---

## P2 — 回程改造：本地出网 → 交还防火墙

**目标**：让"判定为不翻墙"的流量回到防火墙，由防火墙正常转发。

### 已定：方案 B（TPROXY 全量）

```
netfilter：办公网段全部 TPROXY 到 mihomo（保留真实客户端源 IP）
mihomo：白名单命中 → 出口池；其余 → DIRECT 出站
DIRECT 出站走本机默认路由 → 下一跳是防火墙 → 交还
```

选它的理由：
- ✅ **与上游完全一致**，`rules.go` / `sniffer.go` 一行不改，风险最低
- ✅ 能嗅探 SNI/Host/QUIC，QUIC 443、非标端口 TLS 都能正确分类
- ✅ 纯 IP 目标、Telegram 这类硬编码 IP 应用天然支持
- ✅ 入向源 IP 由 TPROXY 保留，per-terminal 成立，"用户身份用源 IP 够用"这条满足
- ⚠️ 不翻墙的流量源 IP 变成旁挂机地址（本质是 NAT）

**这个取舍已确认成立**，因为终端识别依赖的是**入向**源 IP（TPROXY 保留），
而不是回程源 IP。回程 NAT 的行为与办公网出口 NAT 无异，终端无感。

> **仍待你在部署时确认的一项**：办公网的内网系统有没有**基于源 IP 的 ACL**
> （如"只有 10.1.x.x 能访问财务系统"）？若有，回程 NAT 会打穿这些策略，
> 那时才需要回到方案 A。若没有，方案 B 一路到底。

被否决的方案 A（DNS 应答驱动 nft 集合 + 保源 IP 转发）保留记录在此，
以备将来内网 ACL 需求出现时回头取用：其代价是判定入口只剩 DNS，
终端自带 DoH / ECH / 纯 IP 访问全部漏判，且需自写 DNS-TTL 与 nft 集合同步逻辑。

### 实现

| 文件 | 改动 |
|---|---|
| `internal/config/config.go` | 新增 `Node.Return.GatewayIP` / `Node.Return.Iface` |
| `deploy/node/install.sh` | 安装默认路由：`ip route replace default via <Return.GatewayIP> dev <egress>`；`precheck` 校验 `Return.GatewayIP` 非空 |
| `deploy/node/iproute.sh` | 确认 FORWARD 链**没有**挂 TPROXY（回程是 FORWARD，不能被打标） |
| `internal/mihomo/renderer.go` | 出站绑定 `EgressIface`，确保出墙流量不走默认路由 |

**原理注记**：回程是 FORWARD 语义，不打 fwmark，因此不会被
`ip rule fwmark 0x44 lookup 101` 二次劫持。这是方案 B 不需要单独回程口的原因——
但前提是你的防火墙 PBR 指定了原入接口（已确认）。

**验证**：
- 不翻墙：`curl` 一个国内站点，在**防火墙的会话表**上应能看到这条会话（证明流量确实回去了，而不是本机偷偷出网）
- 翻墙：`curl` 白名单站点，出口 IP 应是机场节点 IP，不是旁挂机本地出口 IP
- 环路检查：抓包确认回程包没有再被引流回本机

---

## P3 — 自检与降级（**本项目的核心增量**）

**目标**：把"机器活着"和"数据面健康"这两件事解耦，让防火墙的 IP-Link 探针反映后者。

见 `README.md` §5 的背景分析：华为 IP-Link 只支持 `icmp`/`arp`，
而 ICMP 探活探的是内核——mihomo 崩了、nft 被刷了、出口池全挂，
这三种情况下机器照样秒回 ICMP，防火墙会把整个办公网灌进黑洞。

1. 新建 `internal/watchdog/`（本项目的第一个全新包）：
   - `watchdog.go` —— 主循环、状态机（健康/不健康）、阈值去抖
   - `checks.go` —— 三项自检的具体实现
   - `probeaddr.go` —— 探活地址的增删（`ip addr add/del` 或 nft 规则切换）
   - `watchdog_test.go` —— 状态机单测（重点测抖动、连续失败计数、恢复阈值）

2. 三项自检。**两项复用上游已有能力，一项改为消费上游状态而非重新实现**：

   | 检查 | 实现来源 |
   |---|---|
   | engine 存活 | 复用 `dataplane.Controller` 的 clash-api 客户端 |
   | 数据面规则在位 | **读 `internal/dataplane/assert.go` 的既有状态，不重复实现** |
   | 出口池健康 | 读 `nodescorer` 的既有状态，读一个节点就够 |

   ⚠️ 第二项为什么要这样分工 —— 详见 `CHANGES-FROM-UPSTREAM.md` §六。
   简述：`assert.go`（2026-08-12 事故的产物）已经每 30s 断言规则并做**定点自修复**。
   若 watchdog 也实现检查+修复，会在"摘地址"与"修好"之间来回打架：
   规则被刷掉 → watchdog 摘地址 → 防火墙回切 → assert 修好 → 地址挂回 →
   防火墙又切过来。正确的分工是 **assert 负责修复、watchdog 负责报信**，
   且报信带阈值去抖。

3. 探活地址的开关语义：
   ```
   健康   → 地址在位，应答 ICMP → 防火墙 IP-Link Up   → PBR 生效，流量继续引流
   不健康 → 地址摘除，不回 ICMP → 防火墙 IP-Link Down → PBR 失效，流量回落直连
   ```
   **`liveness_ip` 部署时必填，不设默认值**，且必须独立于 `node.ingress_ip`
   —— 否则摘地址会连 SSH 和 API 一起干掉，你连上去排查的路都没了。
   `install.sh` 的 precheck 拒绝空值，并校验它与 `ingress_ip` 不同。
   建议在 ingress 网段里挑一个空闲地址绑 `lo`；若防火墙用 `arp` 模式探测，
   则须绑物理口（`liveness_iface`），因为 ARP 不能跨三层。

4. **报信与动作分离** —— 新增 `watchdog.auto_failover` 配置项（默认 `false`）：

   | 取值 | 判定不健康时 |
   |---|---|
   | `false`（默认） | 只推飞书告警，探活地址保持应答，防火墙不动作 |
   | `true` | 摘掉探活地址 → IP-Link Down → PBR 失效 → 流量自动回落直连 |

   这样"先观察、后自动"是**改配置**而非改代码，切换不需要重新部署。

5. 接到现有告警通路：状态翻转时经 `internal/notify` 推飞书，
   消息里带上**是哪一项检查失败**——这决定了你收到告警后该查什么。

6. 新增 `deploy/node/turnout-watchdog.service`（systemd 单元，`Restart=always`）。

**交付**：watchdog 可独立运行；两种模式（告警 / 告警+摘地址）都可配置生效。
**验证**：
- `auto_failover: false`：手动 `kill` mihomo → 应**只收到飞书告警**（含失败项），
  探活地址**保持不变**，防火墙 IP-Link 状态不变
- `auto_failover: true`：手动 `kill` mihomo → watchdog 应在
  `interval × fail_threshold` 内摘掉探活地址；防火墙 `display ip-link status` 跟随变为 Down
- 手动恢复 → 应在 `recover_threshold` 后自动挂回，IP-Link 恢复 Up
- **抖动测试**：手动制造单次失败，确认两种模式下都不会触发动作（阈值去抖生效）
- **分工验证**：手动删掉 `ip rule fwmark 0x44`，确认 `assert.go` 在 30s 内修好，
  且 watchdog **没有**因此摘地址（证明先修复、后报信的顺序正确）

> **推进节奏建议**：`auto_failover` 保持默认 `false` 上线，跑一两周观察真实故障率。
> 试用期用户少，手动切回足够。自动回切在"数据面半死"时会给出假的安全感——
> 探针说健康、实际黑洞——反而不如没有。确认故障模式可预期后再置 `true`。

---

## P4 — 端到端验证与切换演练

**目标**：在小范围真实用户上验证，并演练切换。

1. **功能矩阵**（每项都要有明确的预期结果）：

   | 场景 | 预期 |
   |---|---|
   | 国内站点 | 直连，延迟与不走旁挂机一致 |
   | 内网系统（域名） | 直连，走 CN DoH 解析 |
   | 内网系统（纯 IP） | 直连，`MATCH,DIRECT` 兜底 |
   | 白名单海外站点 | 走机场节点，出口 IP 是节点 IP |
   | 同一终端多次访问同一站点 | **同一个出口 IP**（per-terminal 生效，不被风控） |
   | 纯 IP 海外目标（非白名单） | 直连（预期行为，不是故障） |
   | 非标端口私有协议 | 直连（预期行为，不是故障） |
   | DNS 查询 | 由本机应答，国内外分别走对应 DoH |

2. **容量复测**：用上游 `scripts/stress.sh`（需按新的目标列表和网卡名改），
   在旁挂机上重跑，覆盖 `capacity` 配置块里的 50/150。

3. **切换演练**（这是旁挂部署最该练的事）：
   - 在防火墙上手动切回直连 → 确认全网恢复正常，无残留
   - 手动关掉旁挂机 → 确认 IP-Link Down、PBR 失效、流量回落
   - 恢复 → 确认自动/手动切回后服务正常
   - 记录每一步的实际耗时

4. **灰度**：按你的规划，只把少部分用户的源网段放进 PBR 规则，
   观察后再扩大。PBR 规则里的 `source-address` 就是灰度开关。

---

## P5 — 控制台与 API

**按需保留**，默认不做任何改动。上游 25 个 REST 端点 + Arco 控制台编进二进制，
直接可用。

**建议的最小增量**：
- 控制台加一个 watchdog 状态卡片（健康/不健康、上次翻转时间、失败原因）
- 新增 `GET /api/watchdog/status` 供防火墙侧的自动化或你自己的巡检脚本读取

其余不改。除非实际用起来发现别扭，否则不值得动。

---

## 工作量与风险

| 阶段 | 改动量 | 风险 |
|---|---|---|
| P0 | 全局重命名 + 基线 | 低（机械替换，靠测试兜底） |
| P1 | 中（配置 + 部署脚本） | **中** —— 网卡/网段配错会直接不通 |
| P2 | 小（方案 B，已定） | **中** —— 环路与源 IP 是踩坑高发区 |
| P3 | 中大（全新包） | 中 —— 逻辑简单，但阈值调参要靠实测 |
| P4 | 小 | 低 |
| P5 | 小 | 低 |

**最大的两个风险**：
1. **环路**（P2）：回程必须走和引流不同的接口，否则防火墙 PBR 二次命中。
   你已确认防火墙 PBR 指定原入接口、不共用——这条前提必须在上线前实测确认。
2. **假健康**（P3）：ICMP 探活探不到数据面故障。这正是 watchdog 存在的理由，
   也是为什么不建议一上来就开自动回切。

**明确不做的事**（与你的要求一致）：
- 不做双机热备（手动切回）
- 不处理 DoH/ECH 场景
- 不接用户身份源（源 IP 够用）
- 不换出口（继续机场订阅）
- 不换技术选型（继续 mihomo）
