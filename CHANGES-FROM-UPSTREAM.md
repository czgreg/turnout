# 相对上游 leap-gateway 的改动清单

逐包、逐文件的"保留 / 修改 / 重命名 / 删除 / 新增"映射。

**统计**：上游约 95 个源文件。**约 75 个一行不改**，14 个少量修改，4 个重命名，
3 个删除，新增 1 个包 + 4 个文件。

改动高度集中在 `internal/config` + `internal/mihomo/{dns,inbounds}` + `deploy/node/*`。
判定逻辑、打分、订阅、告警、控制台**全部原样保留**。

---

## 一、一行不改（verbatim 复制）

> ⚠️ 本表描述**初始移植时**的状态。2026-10-23 的双出口类改动修改了
> `internal/mihomo/{rules,groups,perterminal}.go` 与 `internal/nodescorer/`，
> 差异见 §八。

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
| `internal/nodeinfo/` | 2 | 节点探针（⚠️ 见 §二，VPN 服务块已换成旁挂链路事实） |

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
  只是配置里的值从上游的内网域换成办公网内网域。
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

### 4.1 飞连专属子系统（连带清掉 sing-box 依赖）

| 文件 | 理由 |
|---|---|
| `internal/whitelistexpand/expander.go` | **607 行。** 它的产出 `GET /api/whitelist/resolved` 在本仓库**零消费者**：数据面不走它（渲染器直接 emit rule-providers 指向 `.mrs`，mihomo 自己加载），前端也完全没有白名单相关代码。它的存在理由写在包注释里 —— 供飞连控制台的"极速模式"消费。 |
| `GET /api/whitelist/resolved` 端点 | 同上。连同 `refreshExpander` / PUT 后的异步刷新、`api.Deps.Expander`、启动时的 warm 协程一起移除。 |
| `scripts/expand-whitelist.py` | 唯一用途是把白名单喂给飞连的域名白名单。 |
| 部署包里的 **sing-box 二进制** | 它被随包分发的**唯一原因**就是 `whitelistexpand` 调 `sing-box rule-set decompile` 展开 geoip。这条链没了，`stage.sh` / `install.sh` 都不再下载或安装它。 |
| `scripts/setup-ssh.sh` 的默认密码 `ppio2026` | 硬编码凭据。改为必填环境变量 `SSH_PASSWORD`，并让 `<user@host>` 参数也成为必填——该脚本会对着你指定的任何主机跑。 |

> **sing-box 不是全部删掉。** 它在这三个位置是**活功能**，保留：
> `internal/subscribe/singbox.go`（解析机场原生返回的 sing-box JSON）、
> `Format` 枚举里的 `singbox` 值、以及 UA 回退探测里的 `sing-box/1.10.7`
> （部分机场按 UA 返回不同内容）。删的是**可执行的并分发的**那份。

### 4.2 上游遗留（greenfield 上永不存在的对象）

| 文件 | 理由 |
|---|---|
| `deploy/node/iproute.sh` 里的 fwmark 0x42 / table 100 清理块 | sing-box 时代 `tun.fwmark: 66 / routing_table: 100` 的遗留。greenfield 部署上从不存在，属于死代码。 |
| 同文件的 `LEAP_TPROXY` 链清理块 | 上一代链名的清理。新部署不会有它。 |
| `deploy/node/install.sh` 里的 sing-box 服务清理块 | 上游退役 sing-box 数据面时留的保护块。同理。 |

### 4.3 配置与脚本里的节点专属假设

| 位置 | 改动 |
|---|---|
| `Makefile` | `NODE` **不留默认值**（原为 `ops@<host>`），所有触网目标加 `check-node` 守卫；`deploy-92` / `redeploy-92` 合并为通用的 `deploy` / `redeploy`。 |
| `scripts/deploy.sh`、`redeploy-full.sh` | `REMOTE_USER` 从硬编码默认值改为必填。 |
| `scripts/watch-node.sh` | 默认主机与硬编码的 `ops@` 移除；host 参数必填。 |
| `scripts/setup-ssh.sh` | 默认主机移除，见 4.1。 |

> 理由：默认值写死会让人以为这里仍指向作者的某个具体节点。生产节点不进新仓库。

### 4.4 其余

| 文件 | 理由 |
|---|---|
| `deploy/node/install.sh` 中的 feilian 检查项 | `feilian-tun@tun0.service` 的状态检查、tun0 IP 比对等，在旁挂机上无意义。已换成旁挂机检查项（见 PLAN.md P1）。 |
| `docs/ops-*.md`（2 个） | 飞连节点 89/92 的运维记录。节点已下线，且属于上游资产——**留在上游仓库**，新仓库不搬。 |

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

---

## 七、2026-10-22：控制面可达性与引流网段可编辑

### 1. 移除 18080 的 API DROP（`deploy/node/iproute.sh`）

旧行为：mangle PREROUTING 最前面插一条
`-i $INGRESS_IFACE -s $CLIENT_SUBNET --dst-type LOCAL -p tcp --dport $API_PORT -j DROP`，
拒绝被引流网段访问控制面。副作用是**站在该网段里的操作员也连不上 `/ui/`**：
节点 10.1.3.15 的 `client_subnet` 是 `192.168.0.0/16`，管理机
`192.168.1.117` 落在里面，于是页面打不开而进程监听正常。

这条 DROP 本来就是冗余的 —— TPROXY 链首条已是
`-m addrtype --dst-type LOCAL -j RETURN`，目的为本机的流量不会进 mihomo。
删掉后：网段终端 → 本机 18080 由内核本地投递，nft input 链放行，
**不经过代理**。升级时 `purge_prerouting()` 会清掉老安装留下的 DROP。

副作用：控制面在该网段内不再有网络层隔离，只剩 `api.token` 一层
（当前为空）。这是 2026-10-19「测试期对外开放」决定的延续，内网可信前提成立。

### 2. nft.conf 渲染抽成脚本（`deploy/node/render-rules.sh`）

原来只在 `install.sh` 的 shell 里。现在控制面改网段后也要重渲染，
两份实现必然漂移，所以抽成唯一实现；`install.sh` 与 API 都调它。
脚本内置 `nft -c` 语法自检，坏模板进不了线上。

### 3. 新增 `GET/PUT /api/node/network`

`client_subnet` 是唯一一个改动会逃出 turnout-gateway 进程的配置字段：
它同时被 `/etc/turnout/env`、`nft.conf`、`turnout-nft.service` 和数据面消费。
所以保存是一个五步扇出（详见 `docs/api.md`），中途失败会返回 500 并明确
说明「yaml 已落盘、线上规则可能仍是旧值」。

渲染器新增 `SetNode`：`Renderer` 在构造时用 `WithNode` 拷贝了一份 `NodeConfig`，
不重新灌入的话 `fb-<ip>` 分组会一直按旧网段生成 —— API 报新值、mihomo 匹配旧值。

### 4. 前端「网段设置」页（`web/src/pages/Network.tsx`，`#/network`）

编辑 `client_subnet`，保存前二次确认（会短暂中断代理转发），
并在 `api_token_set=false` 时给出无鉴权告警。

### 5. 新增 `GET/PUT /api/node/signal` +「节点信号」卡片

`liveness_ip` / `auto_failover` / `notify_on_state_change` 也搬进控制台。

三个刻意的设计点：

- **保存即重启，返回值描述的是"将要发生"而非"已发生"。** watchdog 在
  `cmd/gateway/main.go` 里构造一次，配置不重启就不生效。用
  `systemd-run --on-active=2 --collect` 排一个**瞬态单元**来重启自己 ——
  普通后台子进程会被本服务的 cgroup 一起杀掉。
- **换地址时同步摘旧地址。** watchdog 只在健康翻转时挂地址，从不清理历史值，
  留着旧 `/32` 会让它继续应答防火墙 IP-Link 探测。
- **前端文案写明"进程崩溃不会自动摘地址"。** 这个地址由内核持有，不属于进程；
  把 `auto_failover` 理解成"进程死了自动摘"的运维会在最需要它的时候误判。
  实际兜底是 systemd 的 `Restart=on-failure`。

> 后续讨论中确认的两个事实，都写进了代码注释与 UI：① watchdog 只能覆盖
> **数据面**故障（mihomo 崩溃 / TPROXY 规则丢失 / 出口池全空），对自身崩溃
> 是盲的；② `auto_failover: false` 时它只报信不动作，防火墙永远看不到 Down。
> 所以建议路径是「先开告警观察，确认无误报后再开自动回切」。

### 6. 新增「通知设置」页（`web/src/pages/Notifications.tsx`，`#/notifications`）

后端五个通知端点早就存在，但前端一个都没接 —— 操作员想配飞书 webhook 只能 curl。
这一页把 `GET /api/notifications/status`、`POST/DELETE /api/notifications/lark`、
`POST /api/notifications/test`、`GET /api/notifications/recent` 全部接上。

两个刻意的处理：

- **密钥不回显。** 服务端只返回 `secret_configured: boolean`；表单留空表示「保持
  已存密钥」，清除走单独的 DELETE（同时删 webhook 地址）。若把留空当成清空，
  一次无心的保存就会静默停掉告警。
- **`signature_required` 默认开启，与服务器一致。** 开启后密钥必填，前端先拦，
  否则操作员会撞上一个莫名其妙的 400。

下方「最近通知」直接读 JSONL 日志，包含投递失败的行 —— 这正是"为什么没收到告警"
的答案来源，不依赖飞书侧可见性。

### 7. 广告拦截（`route.ad_block`）

上线原因：被引流网段终端零配置，网络层拦广告是这套旁挂架构唯一不需要
装客户端的形态。

实现是三行规则，对应三份域名表：

```yaml
rules:
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  ...
  - RULE-SET,category-ads-all,REJECT   # 必须早于 geosite-cn,DIRECT
  - RULE-SET,anti-ad,REJECT
  - RULE-SET,cname-ads,REJECT
  - RULE-SET,geosite-cn,DIRECT
```

| 表 | 规模 | 作用 |
|---|---|---|
| `category-ads-all` | 903 | MetaCubeX，广告交易所主体 |
| `anti-ad` | ~11.2 万 | 中文向列表，纯文本，覆盖中文 App 埋点与广告 SDK |
| `cname-ads` | ~1.17 万 | AdGuard cname-trackers 的"伪装第一方域名" |

三处刻意的取舍：

- **位置**：mihomo 首条匹配，规则若放在 `geosite-cn,DIRECT` 之后，国内站点
  上的广告域名会先命中 CN 直连而永远拦不到。
- **列表**：`category-ads-all` 是 `category-ads`（843）的**超集**，不是子集。
  多出的 60 条正是 adnxs / casalemedia / openx / pubmatic / taboola 这些主流
  广告交易所，同时也带进 `+.sentry.io` / `+.segment.io` / `+.clearbit.com`
  这类追踪与开发者域名——选它是因为交易所的覆盖，代价一并接受。
- **没有排除名单**：按产品决定不做。代价是误杀只能整体关闭——这一点写进了
  控制台开关的确认弹窗和 `docs/api.md`，不留给运维自己发现。已知的第一例是
  `img1.126.net`（163 系图片 CDN，在 anti-AD 里）。

规则集缺失是**静默**的：实测 mihomo 对该情况只打一行
`initial rule provider ... no such file` 然后继续服务，规则匹配不到任何东西。
所以 `scripts/stage.sh` 无条件打包三份文件（下载失败时**中断构建**），并对两份
文本表做归一化（去注释行、去 `*.` 前缀），`PUT /api/ad-block` 在任一份缺失时
返回 409 并列出文件名——"以为在拦"比"没拦"更糟。

控制台位置：「分流白名单 → 广告拦截」卡片，走独立端点 `GET/PUT /api/ad-block`，
不并入白名单的整存模型（它不是白名单文档的一部分，且立即生效）。

---

## 八、2026-10-23：双出口类（AI / 其他）

背景：单出口池只收美国节点，冷开 YouTube 约 3 s。新增「分类池」：一个终端
同时拥有两个稳定出口——AI 流量走美国，其他白名单流量走亚洲。

- **配置**：`PoolConfig` 新增 `node_pattern` / `size` / `per_terminal` /
  `domain_suffix`。带任一字段的池成为「分类池」，拥有自己的候选集和路由；
  旧池（只有 `requires_passing` / `rule_sets`）行为完全不变。
  `node_pattern` 是 Go RE2，不支持 lookahead/lookbehind。
- **评分**：候选发现取全局 pattern 与所有分类池 pattern 的并集；
  `computePoolMembers` 按 pattern + long-EWMA + `size` 选成员，并用
  `SwapThresholdScore` 做粘滞替换，避免池抖动。
- **渲染**：分类池 `per_terminal: true` 生成 `fb-<pool>-*` 组和
  `perterm-<pool>` 子规则；`false` 则直接路由到共享组。空池渲染
  `select,[DIRECT]` 兜底（mihomo 不接受空组）。`domain_suffix` 规则先于
  rule_sets 和全局 whitelist，保证 Gemini 等具体域名不被更宽的 geosite 抢走。
- **API**：`/api/pool/terminal` 增加 `pools` 数组（每个分类的 primary/
  secondary/active）；`/api/proxies/active` 的 `pools[]` 现在包含命名分类池
  （它们不在 `out.All` 里，旧循环看不到）。
- **取舍**：同一终端在 AI 类和其他类各有一个 IP；Gemini 归 AI（美国），
  YouTube 归其他（亚洲）。详见 `docs/design-dual-class-exit.md`。
- **2026-10-23 后续命名**：默认池 `us-pool` 更名为 `default-pool`（代码常量、
  mihomo 组名、`MATCH,default-pool`、API/UI/文档）。上面的上游对照表仍写
  `us-pool`，那是上游的历史名称。
