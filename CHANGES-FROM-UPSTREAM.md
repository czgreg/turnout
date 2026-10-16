# 相对上游 leap-gateway 的改动清单

逐包、逐文件的"保留 / 修改 / 重命名 / 删除 / 新增"映射。

**统计**：上游约 95 个源文件。**约 75 个一行不改**，14 个少量修改，4 个重命名，
3 个删除，新增 1 个包 + 4 个文件。

改动高度集中在 `internal/config` + `internal/mihomo/{dns,inbounds}` + `deploy/node/*`。
判定逻辑、打分、订阅、告警、控制台**全部原样保留**。

---

## 一、一行不改（verbatim 复制）

### 判定逻辑 —— 本项目最核心的复用

| 包/文件 | 为什么不改 |
|---|---|
| `internal/mihomo/rules.go` | 白名单规则的顺序与语义完全适用。最后一行 `MATCH,DIRECT` 在旁挂场景下恰好就是"兜底交回防火墙" |
| `internal/mihomo/sniffer.go` | TLS SNI / HTTP Host / QUIC ALPN 嗅探与旁挂无关。`parse-pure-ip` + `override-destination` 是分类率的关键 |
| `internal/mihomo/groups.go` | 出口池分组（us-pool、fb-`<ip>` 等） |
| `internal/mihomo/proxies.go` | 节点 → mihomo proxy 的转换 |
| `internal/mihomo/perterminal.go` | per-terminal HRW 分配，一个终端一个出口 IP |
| `internal/mihomo/*_test.go` | 连同 golden 测试一起搬，保住回归防线 |

### 出口与调度

| 包 | 文件数 | 为什么不改 |
|---|---|---|
| `internal/subscribe/` | 11 | 订阅拉取解析（clash / sing-box / uri / sip008），与部署位置无关 |
| `internal/nodescorer/` | 17 | 双窗 EWMA 打分、池决策、紧急降级。这是上游最值钱的部分 |
| `internal/rulesets/` | 3 | 规则集下载与 .mrs 缓存 |
| `internal/nodeinfo/` | 2 | 节点探针 |
| `internal/whitelistexpand/` | 1 | 白名单域名展开 |

### 支撑

| 包 | 为什么不改 |
|---|---|
| `internal/notify/` | 飞书告警（HMAC + JSONL 兜底）。watchdog 直接复用它推送状态翻转 |
| `internal/configstore/` | 配置存档 |
| `internal/api/*` | 25 个 REST 端点。见下方"P5"——按需保留，默认不动 |
| `web/` | Arco Design 控制台，含已提交的构建产物 |

---

## 二、少量修改（逐处说明）

### 2.1 `internal/config/config.go` —— schema 改动的主战场

| 改动 | 上游 | 新项目 |
|---|---|---|
| 字段改名 | `Node.Tun0GatewayIP` | `Node.IngressIP` |
| 新增 | — | `Node.IngressIface` |
| 新增 | — | `Node.Return.GatewayIP` |
| 新增 | — | `Node.Return.Iface` |
| 新增 | — | `WatchdogConfig`（整块，含 `Checks` 子结构、`LivenessIP`/`LivenessIface`、`AutoFailover`） |
| 校验 | `precheck` 里的 tun0 相关断言 | 换成 ingress 相关断言；**新增** `LivenessIP` 非空 且 ≠ `IngressIP` 的断言 |

`node.client_subnet` / `node.egress_iface` / `data_plane.*` / `route.*` / `pools.*`
**字段名与语义全部不变**——这保证了 `configs/gateway.example.yaml` 的 diff 最小，
也保证运维的既有认知不作废。

**不做**：方案 A（DNS 应答驱动 nft 集合）已否决，因此**不新增** `DNS.SetDriven` 及其
相关的集合 TTL 同步逻辑。这是本次决策砍掉的最大一块工作量——原本需要自写
DNS 应答 → nft 集合的写入、TTL 过期清理、以及集合内容与 mihomo 判定的双写一致性问题。
方案 B 下全部不需要。

配套：`internal/config/example_test.go` 要同步（它断言示例配置能解析）。

### 2.2 `internal/mihomo/dns.go`

- `buildDNS()` 的 `listen` 兜底从 `r.node.Tun0GatewayIP + ":53"` → `r.node.IngressIP + ":53"`。
- `FakeIPSkipSuffixes` 的**语义不变**（内网后缀走 CN DoH），
  只是配置里的值从飞连的 `paigod.work` / `feilian.cn` 换成办公网内网域。
  字段名保留历史命名，不改——见 `configs/gateway.example.yaml` 里的说明。
- `enhanced-mode` 保持 `redir-host`，理由见 README §3。
- **不做**：DNS 应答驱动 nft 集合的输出（方案 A 已否决）。

### 2.3 `internal/mihomo/inbounds.go`

- `buildTUN()` 的判定条件 `r.node.Tun0GatewayIP == ""` → `r.node.IngressIP == ""`。
- **TUN 保持 `enabled: false`**。上游注释（第 23-30 行）已明确记录：TUN 的两种 stack
  都把客户端源 IP 塌缩成 `198.18.0.0`，per-terminal 必须走 TPROXY。旁挂场景同样成立。
  方案 B 下入向仍是 TPROXY 全量，因此本文件的改动仅限上述条件重命名。

### 2.4 `internal/mihomo/renderer.go`

- 出站绑定 `EgressIface`，确保出墙流量不走本机默认路由
  （默认路由指向防火墙，不绑的话出墙流量会被送进防火墙绕一圈）。
- 写文件的"每文件私有临时文件"逻辑（`renderer_write_test.go` 覆盖的那个修复）
  **保持不动**——那是 2026-09-24 修 torn config 的成果。

### 2.5 `internal/dataplane/assert.go` —— ⚠️ 见文末"对 PLAN.md 的修正"

这个包已经做了 watchdog 想要的一半：每 30s 断言数据面规则在位并自修复，
且修复后仍告警（不静默自愈）。**不要重写它**，让 watchdog 消费它的状态。

### 2.6 `internal/leaphttp/leaphttp.go`

- 包名与注释里的 `leap-gateway` / `10.8.x.x` 表述改为新项目。
- **逻辑不动**：核心是"任何出海的 Go 出站都经 127.0.0.1:11080 走池"，
  否则直连撞墙。这条在旁挂机上同样成立。
- 注意：它引用的 `dataplane.LeapInternalProxyPort = 11080` 常量名可保留，
  改常量名会牵动多处，收益为零。

### 2.7 `cmd/gateway/main.go`

- 装配 watchdog（新增一个组件启动）。
- 其余生命周期逻辑（订阅调度、打分循环、API 服务）不动。

### 2.8 `cmd/render-mihomo/main.go`

- 渲染参数随 config schema 同步。

### 2.9 `cmd/selftest/main.go`

- 仅 import 路径随模块重命名。

---

## 三、纯机械重命名（无逻辑变化）

| 对象 | 上游 | 新 |
|---|---|---|
| Go module | `github.com/leap-gateway/leap-gateway` | `github.com/turnout-gateway/turnout-gateway` |
| 所有 Go import | 同上 | 同上 |
| 配置目录 | `/etc/leap/` | `/etc/turnout/` |
| 数据目录 | `/var/lib/leap/` | `/var/lib/turnout/` |
| systemd 单元 | `leap-gateway/-mihomo/-nft.service` | `turnout-gateway/-mihomo/-nft.service` |
| iptables 链 | `LEAP_TPROXY` | `TURNOUT_TPROXY` |
| 环境文件 | `/etc/leap/env` | `/etc/turnout/env` |
| logrotate | `logrotate-leap.conf` | `logrotate-turnout.conf` |

> **不做兼容层。** 新项目是新部署，不是原地升级。留两套命名只会在排查时浪费时间。
> `LEAP_*` 环境变量名同样改掉。

---

## 四、删除

| 文件 | 理由 |
|---|---|
| `deploy/node/install.sh` 中的 feilian 检查项 | `feilian-tun@tun0.service` 的状态检查、tun0 IP 比对等，在旁挂机上无意义。**函数骨架保留**，换检查项（见 PLAN.md P1） |
| `docs/ops-*.md`（2 个） | 飞连节点 89/92 的运维记录。节点已下线，且属于上游资产——**留在上游仓库**，新仓库不搬 |
| `deploy/node/leap-nft.service` 中的 `PartOf=leap-mihomo` | 上游注释提到这条链曾在 89 上泄漏到宿主 SSH 会话。重新评估绑定关系 |

> `docs/design-*.md`（3 个：资格集选择、池容量、准入质量门）**建议搬过来**——
> 它们记录的是打分与池设计的取舍，与部署位置无关，是有效的设计依据。

---

## 五、新增

| 文件 | 作用 |
|---|---|
| `internal/watchdog/watchdog.go` | 主循环 + 健康状态机 + 阈值去抖 |
| `internal/watchdog/checks.go` | 三项自检（engine / 规则 / 池），其中规则项**消费 `dataplane/assert.go` 的状态** |
| `internal/watchdog/probeaddr.go` | 探活地址的摘挂（`ip addr add/del`） |
| `internal/watchdog/watchdog_test.go` | 状态机单测：抖动、连续失败计数、恢复阈值 |
| `deploy/node/turnout-watchdog.service` | systemd 单元，`Restart=always` |
| `configs/gateway.example.yaml` | 重写（已在本仓库） |
| `README.md` / `PLAN.md` / `CHANGES-FROM-UPSTREAM.md` | 本项目文档 |
| `CLAUDE.md` | 搬上游硬规则：**⛔ 永不动节点订阅** |

**不搬**：`gateway`（9.7MB 编译产物）、`build/`、`.cache/`。

---

## 六、⚠️ 对 PLAN.md 的修正

写本文档时读 `internal/dataplane/assert.go` 才发现，PLAN.md P3 里
"watchdog 新增三项自检"的**第二项与 `assert.go` 职责重叠**：

`assert.go` 已经实现了：
- 每 30s 周期性断言数据面规则在位
- 检查失败时**最小化定点自修复**（刻意不跑 `iproute.sh up`，避免中断在线流量）
- 修复后**仍然告警**，不静默自愈

这与 watchdog 的检查项 b（规则在位）是同一件事。

**修正**：watchdog **不重新实现规则检查**，而是：

```go
watchdog.checks.go:
    rulesOK := dataplane.CurrentAssertState().AllOK()   // 读 assert.go 的现有状态
```

这样做的额外好处：`assert.go` 有自修复能力，watchdog 没有。两者职责应当清晰——
- `assert.go`：**修复**瞬时/外部导致的规则丢失（如 networkd 刷掉 policy rule）
- `watchdog`：**对外报信**，全部检查通过才维持探活地址

若把修复逻辑塞进 watchdog，会在摘地址和修复之间打架：
规则被刷掉 → watchdog 摘地址 → 防火墙回切 → assert.go 又修好了 → 地址挂回 → 防火墙又切过来，
形成无意义的来回切换。**先修复、后报信，且报信要有阈值去抖**——这是正确的分工。

PLAN.md P3 第 2 条的表格已按此更新。
