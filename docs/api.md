# Turnout · 道岔网关 API

控制面 HTTP API。base URL：`http://<node-ip>:18080`（端口由 `api.listen` 控制）。

---

## 认证

`gateway.yaml` 配置 `api.token` 后，除 `/healthz` 外所有端点需要：

```
Authorization: Bearer <token>
```

token 为空时不鉴权。

---

## 端点速览

| 方法 | 路径 | 功能 | 认证 |
|---|---|---|---|
| GET | `/healthz` | 可达性探测 | 无 |
| GET | `/ui/` | Web 控制台（静态页面） | 无 |
| GET | `/api/status` | 节点总体状态 + 容量 | ✓ |
| GET | `/api/nodes` | 全量节点列表 | ✓ |
| GET | `/api/nodes/health` | NodeScorer 评分 + probe + passive stats | ✓ |
| GET | `/api/proxies/active` | 数据面活跃状态快照 | ✓ |
| POST | `/api/proxies/select` | 手动切换 selector 成员 | ✓ |
| GET | `/api/pools` | 分类池只读配置（gateway.yaml `pools:`） | ✓ |
| GET | `/api/subscriptions` | 订阅列表 | ✓ |
| POST | `/api/subscriptions` | 新增订阅 | ✓ |
| PUT | `/api/subscriptions/{name}` | 修改订阅 | ✓ |
| DELETE | `/api/subscriptions/{name}` | 删除订阅 | ✓ |
| POST | `/api/subscribe/refresh` | 立即刷新订阅 | ✓ |
| GET | `/api/subscribe/refresh-interval` | 查看刷新间隔 | ✓ |
| PUT | `/api/subscribe/refresh-interval` | 修改刷新间隔 | ✓ |
| GET | `/api/whitelist` | 白名单配置 | ✓ |
| PUT | `/api/whitelist` | 整体替换白名单 | ✓ |
| GET | `/api/rule-sets` | 可用 geosite/geoip catalog | ✓ |
| GET | `/api/ad-block` | 广告拦截开关状态 + 规则集是否就位 | ✓ |
| PUT | `/api/ad-block` | 开关广告拦截（热重载 mihomo） | ✓ |
| GET | `/api/adult-block` | 成人内容封禁开关 + 规则集 + 豁免名单 | ✓ |
| PUT | `/api/adult-block` | 开关成人内容封禁 / 更新豁免（热重载 mihomo） | ✓ |
| GET | `/api/node/network` | 引流网段 + 入口网卡/地址 | ✓ |
| PUT | `/api/node/network` | 修改 `client_subnet`（重建防火墙规则并重启相关单元） | ✓ |
| GET | `/api/node/signal` | 探活地址 + watchdog 开关 | ✓ |
| PUT | `/api/node/signal` | 修改探活地址 / `auto_failover`（重启控制面） | ✓ |
| GET | `/api/pool/terminal?ip=X` | 查询某 terminal IP 的出口节点 + 健康 | ✓ |
| GET | `/api/pool/transitions?limit=N` | 池组成变更审计日志 + 当前隔离名单 | ✓ |
| POST | `/api/pool/rollback` | 回滚最近 N 次池变更 + 隔离被回滚节点 | ✓ |
| GET | `/api/notifications/status` | 通知系统配置快照（不含 secret） | ✓ |
| POST | `/api/notifications/lark` | 设置/更新 Lark webhook url + secret | ✓ |
| DELETE | `/api/notifications/lark` | 移除 Lark webhook（停止外发，本地日志保留） | ✓ |
| POST | `/api/notifications/test` | 同步发一条测试消息验证 webhook | ✓ |
| GET | `/api/notifications/recent?limit=N` | 本地 JSONL 日志最近 N 条 | ✓ |
| GET | `/api/watchdog/status` | 旁挂健康判定（探活地址 / 自检项 / 计数） | ✓ |

---

## GET /healthz

```json
{"ok": true}
```

---

## GET /ui/

内置 Web 控制台（React + Arco Design，源码在 `web/`，构建产物在
`internal/api/ui/`，用 `go:embed` 编进二进制）。总览 + 节点状态 + 订阅管理 +
终端查询 + 池变更审计 + 网段设置 + 通知设置。`/ui` 会 301 到 `/ui/`；各页面地址为
`/ui/#/overview`、`#/nodes`、`#/subs`、`#/whitelist`、`#/terminal`、
`#/transitions`、`#/network`、`#/notifications`。

控制台读取的端点：`/healthz`、`/api/status`、`/api/proxies/active`、
`/api/nodes/health`、`/api/subscriptions`（含 POST / PUT / DELETE）、
`/api/subscribe/refresh`、`/api/subscribe/refresh-interval`、
`/api/whitelist`（含 PUT）、`/api/rule-sets`、
`/api/pool/transitions`、`/api/pool/terminal`、`/api/node/network`（含 PUT）。
改这些端点的响应结构时，
同步改 `web/src/types.ts`，并跑 `make ui`。

分流白名单页（`#/whitelist`）**整体替换**语义：页面持有的是完整白名单草稿，
保存时把整份 body PUT 回去，而不是发增量。确认框会逐条列出增/删项，
并在有规则集尚未下载时提示保存会先拉取（最坏 60 秒）。

**不鉴权，但只返回静态文件**（html / css / js）——页面本身不含节点数据或
凭据，所有真实数据由浏览器带 `Authorization: Bearer` 去请下面的 `/api/*`。
浏览器导航无法携带自定义请求头，给 HTML 本身鉴权只会把 token 逃到 query
或 cookie（即日志与浏览历史），所以这里不包 `s.auth`。可达范围仍由
`api.listen` 与节点 nft 规则控制（被引流终端网段固定拒绕）。

前端对接注意：
- `GET /api/subscriptions` 的 `url` 是脱敏值，**不能**回填给 `PUT`（会把
  `token=abcd***ef01` 写进生产）。UI 编辑时清空 URL 输入框，并在提交前拦
  含 `***` 的值。
- 订阅增删改与 `POST /api/subscribe/refresh` 会重载 mihomo（约 3–5s 中断）。

---

## GET /api/status

```json
{
  "engine_ok":       true,
  "last_refresh":    "2026-06-06T12:00:00Z",
  "node_count":      136,
  "subscriptions":   4,
  "pool_size":       19,
  "pool_eligible":   19,
  "pool_total":      22,
  "pool_last_update":"2026-06-06T11:58:00Z",
  "capacity": {
    "sustained_max_users": 50,
    "degraded_max_users":  150,
    "measured_at":         "2026-06-07",
    "measured_with":       "stress.sh on 89+92 / mihomo v1.19.26 / 941d55f / TPROXY+per_terminal"
  }
}
```

| 字段 | 说明 |
|---|---|
| `engine_ok` | mihomo clash-api `/version` 可达 |
| `pool_size` | 实际承载流量的 default-pool 成员数（InPool，即 per-terminal HRW 抽取的集合大小）。 |
| `pool_eligible` | **仅**通过 liveness 门的节点数（`tier1_count` = `len(qualifiedNodes)`，含无历史节点的 benefit-of-doubt）。**不扣除准入质量门** —— 质量门在 `computeEligibleSetLocked` 里另算。所以 `pool_eligible >= pool_size` 是常态，且与 K 无关：92 在 2026-09-09 读到 12 vs 7，多出的 5 个全部因 `fail_rate` 被拒。读作"活着且可达"，不是"够格入池"；被拒原因看日志 `admission refused on quality`。（旧字段 `pool_qualified` 名为"合格数"实为 InPool，已拆开。） |
| `pool_total` | NodePattern-匹配的候选总数。 |
| `pool_last_update` | default-pool 成员最近一次变更时间。变更频率 ≈ 订阅增减节点频率（小时-天级）。 |
| `capacity` | 离线压测得出的单机上限，未配置时不返回 |

---

## GET /api/nodes

全量节点列表（含非 US 节点）。

```json
[
  {"tag": "ctc-02/US-C30-01", "type": "vless", "server": "us01.example.com", "source": "ctc-02"}
]
```

---

## GET /api/nodes/health

NodeScorer 评分快照。503 = `node_qualify.enabled=false`。

post Plan-A 语义注意：
- `qualified` 与 `in_pool` 解耦了。`qualified` 是节点的"诊断口径"（基于探针窗口判断该节点活/通），`in_pool` 是 default-pool 的实际成员资格。**default-pool = 全部候选节点（只要 NodePattern 匹配），永远不剔除**；mihomo 的 LoadBalance + 30s 健康检查在 per-flow 层自动跳过死节点。所以 `in_pool=true qualified=false` 是正常状态（节点暂时探针失败但留在 pool 里）。
- `thresholds` 块（`MaxRTTP50Ms / MaxRTTP95Ms / MaxJitterMs / MaxFailRate`）**仅为观察用**，不再 gate default-pool。要看一个节点的真实 RTT/抖动表现就读这些字段；要看是否被 mihomo 路由就读 `in_pool`。
- 命名池（如 openai-pool）成员资格仍然由探针 gating，但用 K=3 滑动窗口 + 多数规则：节点要 ≥ 2/3 探针通过才进，要 ≥ 2/3 探针失败才掉出。单次 CF 噪声不再翻转命名池。

```json
{
  "qualified": 18, "total": 19,
  "last_pool_update": "...", "last_scored_at": "...",
  "thresholds": {"MaxRTTP50Ms":500, "MaxRTTP95Ms":800, "MaxJitterMs":300, "MaxFailRate":0.25, ...},
  "probes": {
    "openai-api": {"url":"https://api.openai.com/v1/models", "interval_sec":300, "passing":18, "total":19}
  },
  "nodes": [
    {
      "name": "ctc-02/US-C30-01", "sub": "ctc-02",
      "alive": true,
      "rtt_p50_ms": 155, "rtt_p95_ms": 165, "jitter_ms": 10,
      "fail_rate": 0.0, "throughput_bps": 0,
      "qualified": true, "in_pool": true,
      "strikes": 0, "ok_rounds": 12, "reason": "",
      "probes": {
        "openai-api": {
          "ok": true, "status_code": 401, "cf_mitigated": false,
          "latency_ms": 320, "last_checked_at": "2026-06-06T12:00:00Z"
        }
      },
      "passive": {
        "active_conns": 3, "closed_window": 12, "failed_window": 0,
        "fail_rate": 0.0, "sample_window_sec": 600
      }
    }
  ]
}
```

| 字段 | 说明 |
|---|---|
| `qualified` | 该节点最近 5 个 mihomo 探针里是否有任何成功。仅为诊断字段，不影响 default-pool 成员。 |
| `in_pool` | 实际是否在 default-pool 中。post Plan-A：所有 NodePattern 匹配的候选都是 true。 |
| `reason` | 不合格原因。常见值："dead"（探针全失败 + alive=False）、"no successful probes in last 5"（窗口内全失败）、"no probe history yet (benefit of doubt)"（首次进池前的过渡状态，仍计为 qualified=true）。 |
| `strikes` / `ok_rounds` | 连续不合格 / 合格的 scoring 轮数，仅诊断用。 |
| `probes` | 顶级：各 probe 全局通过率；节点级：每个 probe 的最新结果。命名池 gating 用 K=3 窗口的多数规则，不只看最新结果。 |
| `probes[].cf_mitigated` | CF challenge header 命中（status 200 但实为 challenge）→ ok=false |
| `probes[].latency_ms` | 真实等待时长，失败时为实际超时值（如 10003ms），不是 0 |
| `passive` | 从 `/connections` 被动推导，纯本地无机场流量；无连接时不返回 |
| `passive.fail_rate` | 关闭时传输 < 2KB 的连接占比（可能 RST / dead egress） |

---

## GET /api/proxies/active

数据面活跃状态快照。15 秒内判断是否需要介入的主要运维视图。

```json
{
  "node": {"hostname": "turnout-node-a", "kernel": "...", "os": "Ubuntu 22.04", "uptime_seconds": 86400},
  "ingress": {
    "ingress_iface_up": true,
    "ingress_ip_present": true,
    "return_route": "default via 10.255.255.1 dev ens19",
    "liveness_up": true
  },
  "turnout": {
    "gateway_version": "0d7432d",
    "engine": "mihomo",
    "engine_version": "v1.19.26",
    "services": {"turnout-gateway": "active", "turnout-mihomo": "active", "turnout-nft": "active"},
    "subscriptions_count": 4,
    "nodes_parsed": 136,
    "last_refresh": "2026-06-06T12:00:00Z"
  },
  "active_proxy": {
    "reachable": true,
    "active_group": "default-pool",
    "pool_filter": "美国|🇺🇸|\\bUS",
    "pool_mode": "auto",
    "last_swap_at": "2026-06-06T11:58:00Z",
    "pools": [
      {
        "tag": "default-pool", "pool_size": 8, "active": true,
        "egress": {"ip": "12.34.56.78", "country": "US", "asn": "AS???"},
        "nodes": [
          {"tag": "ctc-02/US-C30-01", "delay_ms": 155, "last_check": "...", "fail_rate": 0.0}
        ]
      }
    ]
  }
}
```

| 字段 | 说明 |
|---|---|
| `active_group` | `out` selector 当前指向的 group（`default-pool` / `pin` / `DIRECT`） |
| `pool_mode` | `node_qualify.pool_mode`：`auto`（scorer 自动换池）/ `manual`（手动维护）|
| `last_swap_at` | 池成员最近一次变更时间。频繁变化说明 scorer 在抖动，配合 `/api/pool/transitions` 查原因 |
| `pool_size` | routing pool 成员数（K-gating top-K）。K-gating 未启用时等于所有合格候选数 |
| `nodes[]` | 当前 routing pool 成员（K-gating top-K 子集）。scorer 不活跃时降级为全量 default-pool 成员 |
| `nodes[].fail_rate` | 来自 NodeScorer 的探针失败率（0.0–1.0）。scorer 不可用时为 -1 |
| `nodes[].delay_ms` | mihomo url-test 最近一次延迟（ms）。0 表示尚无测量 |
| `pools[].egress` | 该池的公网出口 IP + 地理位置，缓存 60s。经 loopback 监听 `127.0.0.1:11082`（`turnout-egress`，钉在 `out` 上、不查规则表）探测 ipinfo.io，fallback 1.1.1.1 trace。load-balance 按目标哈希，所以这是池内**一个**存活成员的出口，代表池的地区，不代表每个终端的节点（终端的节点看 `/api/pool/terminal`）。mihomo 重启后约 1 分钟内健康检查未完成，可能探测失败或命中刚死的节点 |

`pools[]` 同时包含 `out` 链上的 `default-pool` 和所有命名分类池（如 `ai-pool`）。
命名池不是 `out` 的成员，因此 `active=false`；`egress` 探针目前只覆盖默认
`default-pool`，分类池的 `egress` 留空。

---

## POST /api/proxies/select

手动切换某个 Selector 组到指定成员。

```json
{"selector": "out", "name": "pin"}
{"selector": "pin", "name": "ctc-02/US-C30-01"}
{"selector": "out", "name": "DIRECT"}
```

成功返回 200 + `/api/proxies/active` 当前快照。失败：400（selector 类型不是 Select）、404（selector 或 name 不存在）。

override 不 sticky：NodeScorer 只管 default-pool 成员，不回写 selector 指针。

---

## GET /api/subscriptions

```json
[
  {
    "name": "ctc-02",
    "url": "https://47.x.x.x:9999/...?token=abcd***ef01",
    "enabled": true,
    "format": "auto",
    "user_agent": "sing-box/1.10.7",
    "nodes_count": 6,
    "last_refresh": "2026-06-06T12:00:00Z",
    "health": "ok",
    "user_info": {
      "upload": 55308050547,
      "download": 483283111900,
      "total": 536870912000,
      "expire": 1795515130
    }
  }
]
```

字段说明：

| 字段 | 含义 |
|---|---|
| `health` | `ok` / `fetch_error` / `parse_error` / `zero_nodes` |
| `health_err` | 非 ok 时的失败详情（仅错误时出现） |
| `user_info` | 来自上游 `Subscription-Userinfo` 响应头；机场未下发则该字段缺失 |
| `user_info.upload/download/total` | 字节数；`total=0` 表示不限量 |
| `user_info.expire` | Unix 秒；`0` 表示无到期时间，过去的时间表示已到期 |
| `gated_count` | 被过滤掉的客户端提示型伪节点数（如「请改用 FlClash」「内核不支持 AnyTLS」）。与 `health=zero_nodes` 同时出现表示机场拒绝了我们当前的 UA |

`user_info` 和 `gated_count` 只反映最近一次 refresh 的结果（`POST /api/subscribe/refresh`
或周期刷新），不会单独发起请求。

## POST /api/subscriptions

```json
{"name": "new-sub", "url": "https://...", "format": "auto", "user_agent": "clash.meta/v1.19.26"}
```

成功 201 + 完整列表。立即触发 refresh + reload（~3-5s 中断）。

## PUT /api/subscriptions/{name}

```json
{"url": "https://...", "user_agent": "clash.meta/v1.19.26"}
```

### user_agent 常用值

不同机场按 UA 判断客户端版本，UA 不对会返回警告占位节点而非真实节点。省略时用全局默认（`ClashforWindows/0.20.39`），部分面板会将其判定为版本过旧。

| user_agent | 适用场景 |
|---|---|
| `mihomo/1.18.4` | 狗狗加速等按 mihomo 版本放行的面板；通常返回节点数最多 |
| `clash.meta` | 多数 Clash 系面板的通用兼容值 |
| `ClashforWindows/0.20.39` | 全局默认；老面板兼容性好，新面板可能拦截 |
| `sing-box/1.10.7` | 仅限明确要求 sing-box 格式的机场；clash 系面板通常返回 0 节点 |
| `clash-verge/1.7.7` | Clash Verge 系面板 |

排查节点数不及预期时，用不同 UA 各拉一次对比返回的 `name:` 行数，取节点数最多的值。

## DELETE /api/subscriptions/{name}

204。立即触发 refresh + reload。

---

## POST /api/subscribe/refresh

立即拉取所有订阅 → 渲染 → 重启 mihomo。

```json
{"ok": true}
```

一次刷新在开始后**不再受调用方连接控制**：断开连接不会取消渲染和 reload。
耗时上界是 `订阅数 × 2 次 fetch × subscribe.http_timeout`（每个订阅最多
探测两个 UA），实测冷刷新 17–30s，热刷新约 7s。

同一时刻只允许一次刷新，重入返回 `409`：

```json
{"error": "refresh already in progress"}
```

## GET /api/subscribe/refresh-interval

```json
{"seconds": 0}
```

返回当前 scheduler 的间隔。post 2026-06-07 example.yaml 默认 0（关闭周期刷新，靠手动 `POST /api/subscribe/refresh` 触发）；老节点的 yaml 可能仍显式配置非零值。理由见 `configs/gateway.example.yaml` 注释。

## PUT /api/subscribe/refresh-interval

```json
{"seconds": 900}
```

0 = 关闭定时刷新。立即生效 + 持久化到 `/etc/turnout/gateway.yaml`（重启后保留）。

---

## GET /api/whitelist

```json
{
  "mode": "whitelist",
  "geosites": ["geosite-google", "geosite-openai"],
  "geoips": ["geoip-telegram"],
  "domain_suffix": ["ipinfo.io"],
  "ip_cidr": ["149.154.0.0/16"],
  "fake_ip_skip": ["+.corp.example.com"]
}
```

`mode`: `whitelist`（只有命中列表的海外域名走机场）| `overseas`（所有非 CN 走机场）

## PUT /api/whitelist

整体替换（PUT 语义，不是 PATCH）。body 同 GET 结构。

`fake_ip_skip` 写法：`corp.example.com` / `.corp.example.com` / `+.corp.example.com` 均可，统一规范化为 `+.` 前缀。列出的内网域名后缀会走国内 DoH 解析。

`geosites` / `geoips` 中每个 tag 必须在 `/api/rule-sets` catalog 中；不在磁盘则按需从 MetaCubeX 拉取（.mrs），失败 502。

成功触发 mihomo 重启（~3-5s 中断）。

```bash
# 追加一条 domain_suffix
curl -s http://127.0.0.1:18080/api/whitelist \
  | jq '.domain_suffix += ["new-tool.com"]' \
  | curl -s -X PUT -H 'Content-Type: application/json' \
      http://127.0.0.1:18080/api/whitelist -d @-
```

---

## GET / PUT /api/node/network

引流网段（`node.client_subnet`）—— 防火墙 PBR 规则的 source-address。
这是**唯一一个改动会逃出 turnout-gateway 进程**的配置：它同时被
`/etc/turnout/env`、`nft.conf`、`turnout-nft.service` 和数据面消费。

```json
{
  "client_subnet": "10.1.3.0/24",
  "ingress_iface": "ens18",
  "ingress_ip": "10.1.3.15",
  "api_listen": "0.0.0.0:18080",
  "api_token_set": false
}
```

`api_token_set` 只给布尔值，**不回显 token**：控制台需要知道控制面是否无鉴权，
但不需要拿到密钥。

PUT body：`{"client_subnet": "10.1.3.0/24"}`。保存后同步执行：

1. 重写 `gateway.yaml`（`Store.Mutate`）
2. 用 `--print-env` 重新生成 `/etc/turnout/env`
3. 执行 `/etc/turnout/render-rules.sh` 重渲染 `nft.conf`（内含 `nft -c` 语法自检）
4. `systemctl restart turnout-nft.service` 重新下发 nft + TPROXY 规则
5. `SetNode` 后重渲染并热重载 mihomo，按新网段重建 per-terminal 分组
   （`fb-p-<pair>`，同一 HRW 节点对共享一组）

校验（400）：必须是 CIDR、IPv4、网络地址（主机位清零）、前缀在 /8–/31 之间，
且必须包含 `ingress_ip`。

失败语义：以上任一步失败返回 500，body 带 `persisted` / `previous` /
`warning` —— 此时 `gateway.yaml` 已是新值而线上规则可能仍是旧值，需要修好
报告的那一步后重存或重跑 `install.sh`。

> 注意：第 4 步会短暂拆除并重建规则集，期间流量不做代理转发。所以前端
> 保存前必须弹二次确认（`web/src/pages/Network.tsx` 已实现）。

---

## GET / PUT /api/node/signal

watchdog 的运维旋钮 —— 探活地址（防火墙 IP-Link 的探测目标）与两个开关。

```json
{
  "liveness_ip": "10.1.3.250",
  "liveness_iface": "lo",
  "auto_failover": false,
  "notify_on_state_change": true,
  "ingress_ip": "10.1.3.15",
  "return_gateway": "10.1.3.1"
}
```

与 `/api/node/network` 的差别：`liveness_ip` 只被 watchdog goroutine 消费，
既不进 `/etc/turnout/env` 也不进 `nft.conf`，所以应用是「落盘 + 重启」而不是
四步扇出。watchdog 在 `cmd/gateway/main.go` 里构造一次，改配置必须重启进程才生效。

PUT body 四个字段均可选，只改传入的：

```json
{"liveness_ip": "10.1.3.251", "auto_failover": true}
```

保存时依次做三件事：

1. 立即 `ip addr del <旧地址>/32 dev <旧网卡>` —— watchdog 只在健康状态翻转时
   挂地址，不会清理历史值。留着旧 `/32` 会让它继续应答防火墙探测，正是这套
   机制要防的静默故障。
2. `systemd-run --on-active=2` 排一个瞬态单元重启 `turnout-gateway`。用瞬态单元
   而不是后台子进程，是因为本服务 cgroup 内的子进程会随自己一起被杀。
3. 返回 200，此时配置尚未生效。

重启后 watchdog 要连续 3 轮自检全绿（约 30s）才把新地址挂上，这段时间防火墙
看到的是 Down。**换地址时必须同步修改防火墙 IP-Link 的探测目标**，否则它会一直
探测一个本机不再持有的 IP。

校验（400）：合法 IPv4；**不得等于 `ingress_ip`**（摘掉会同时断掉 SSH 和 API，
失去排查手段）；**不得等于 `return.gateway_ip`**（那是防火墙自己的地址）。
与 `install.sh` precheck 的三条守卫一致。

---

## GET / PUT /api/ad-block

广告拦截开关。开启后，渲染出的规则表在 **CN 直连之前**多三行：

```
RULE-SET,category-ads-all,REJECT
RULE-SET,anti-ad,REJECT
RULE-SET,cname-ads,REJECT
```

三份域名表（都由 `scripts/stage.sh` 随部署打包，运行时不下载）：

| tag | 文件 | 规模 | 说明 |
|---|---|---|---|
| `category-ads-all` | `category-ads-all.mrs` | 903 | MetaCubeX，广告交易所主体 |
| `anti-ad` | `anti-ad.txt` | ~11.2 万 | 中文向列表，纯文本 |
| `cname-ads` | `cname-ads.txt` | ~1.17 万 | 伪装成第一方域名的投放域名 |

```json
{ "enabled": true, "rule_set_installed": true }
```

任一份缺失时：

```json
{ "enabled": false, "rule_set_installed": false, "missing": ["anti-ad.txt"] }
```

`rule_set_installed` 是「真的在拦」与「以为在拦」的分界：文件缺失时 mihomo
**不会**启动失败，只打一条 `initial rule provider ... no such file`
然后继续服务，那条规则匹配不到任何东西。所以 PUT 在任一份缺失时返回 **409**，
列出缺的文件名，拒绝打开开关，而不是让它静默空转。

PUT body：`{"enabled": true}`。变更走「落盘 → 重渲染 → 热重载 mihomo」，
不重启进程，约 3–5 秒（三份表合计约 12.4 万域名，首次加载可能更久），只影响
新连接。

语义边界：

- 只阻断广告**请求**（连接建立前 REJECT），不隐藏页面广告位，不拦同域广告。
- 域名来自 TLS SNI / HTTP Host，所以终端自建 DoH 也拦得住；纯 IP 无 SNI 的连接不匹配。
- **CNAME 伪装**：被 AdGuard cname-trackers 收录的伪装域名（约 1.17 万条）拦得到
  ——客户端连的就是伪装域，SNI 正是它本身。未收录的新伪装域拦不到。
- 对**全部被引流终端**生效，**没有按域名豁免**——误杀的处置方式只有整体关闭。
  已知第一例：`img1.126.net`（163 系图片 CDN）在 anti-AD 中。
- 规则集由 `scripts/stage.sh` 无条件打包（约 2.4 MB），任何一份下载失败都会让
  stage 直接失败；两份文本表在打包时去掉注释行与 `*.` 前缀。

---

## GET / PUT /api/adult-block

成人内容封禁开关。开启后，渲染出的规则表在 **CN 直连之前**、广告拦截之后多两行：

```
RULE-SET,category-porn,REJECT
RULE-SET,nsfw,REJECT
```

若配置了豁免，豁免行排在两条 REJECT **之前**：

```
DOMAIN-SUFFIX,<domain>,DIRECT   # whitelist 模式（MATCH 也是 DIRECT）
DOMAIN-SUFFIX,<domain>,out      # overseas 模式（跟随普通海外出口）
```

两份域名表（都由 `scripts/stage.sh` 随部署打包，运行时不下载）：

| tag | 文件 | 规模 | 说明 |
|---|---|---|---|
| `category-porn` | `category-porn.mrs` | 6,520 条 | MetaCubeX；.mrs 里是 `+.domain`，覆盖主域及全部子域 |
| `nsfw` | `nsfw.txt` | ~9.07 万条 | HaGeZi NSFW；stage 归一化为 `+.domain` |

**匹配语义（关键）**：mihomo 的 `behavior: domain` 对**裸域做精确匹配**，
只有 `+.domain` 才覆盖"主域 + 所有子域"。v1.19.26 实测：裸 `x.invalid`
不命中 `www.x.invalid`，`+.x.invalid` 命中。因此：

- MetaCubeX 的 `.mrs` 编译产物已经是 `+.domain`，可直接用；
- HaGeZi 原始文件是裸域，`stage.sh` 必须逐行改写成 `+.domain`，否则
  `www.` 与 CDN 子域全部漏拦；
- 现有的 `anti-ad` / `cname-ads` 仍按裸域下发，属于独立的既有行为，
  本功能没有改动它们。

```json
{ "enabled": true, "rule_set_installed": true, "allow": ["example-health.org"] }
```

GET 的 `allow` 永远是数组，不会是 null。任一份文件缺失时：

```json
{ "enabled": false, "rule_set_installed": false,
  "missing": ["nsfw.txt"], "allow": [] }
```

PUT body：`{"enabled": true, "allow": ["example-health.org"]}`。

- `enabled` 必填；缺失返回 400。
- `allow` 可省略（保持现有豁免不变），显式 `[]` 表示清空。服务端会小写化、
  去重，并接受 `+.domain` / `*.domain` 写法，最终都按 `DOMAIN-SUFFIX` 渲染。
  含空白、`://`、`/` 或没有 `.` 的条目返回 400。
- 任一份规则集缺失时开启返回 **409** 并列出文件名——与广告拦截相同，
  mihomo 不会因缺文件而启动失败，只会让规则静默匹配不到。
- 变更走「落盘 → 重渲染 → 热重载 mihomo」，约 3–5 秒，只影响新连接。

语义边界：

- 这是**域名名单匹配，不是内容识别**。名单外的站点不会被识别；要按页面内容
  判断需要 TLS 解密或终端 Agent，不在这套旁挂架构里。
- 靠 TLS SNI / HTTP Host / QUIC 识别，终端自建 DoH 也绕不过；但浏览器启用
  **ECH** 时 SNI 加密，规则失效。
- 纯 IP 无 SNI、sniffer 端口范围外（非 443/8443、非 80/8080-8880、非 443 QUIC）
  的连接不命中。
- 平台内、搜索引擎图片、即时通讯里的成人内容不在域名名单范围内。
- 终端没有提示页，命中表现为连接重置。
- 豁免不要填白名单里的域名：豁免规则先命中，会把该域名强制成直连。
- 规则集由 `scripts/stage.sh` 硬门禁；缺文件时 stage 直接失败。

---

## GET /api/rule-sets

可用的 geosite + geoip tag catalog（含安装状态）。

```json
{
  "geosites": {
    "catalog": [
      {"name":"geosite-google", "category":"tech", "installed":true, "selected":true}
    ]
  },
  "geoips": {
    "catalog": [
      {"name":"geoip-telegram", "category":"app", "installed":true, "selected":true}
    ]
  }
}
```

`geosite-cn` / `geoip-cn` 是路由基建，不在 catalog 中。

---

## GET /api/pools

分类池的**只读**配置，来自 `gateway.yaml` 的 `pools:`。没有 PUT：池配置是运维资产，
编辑走 yaml。当前成员节点不在这里，用 `/api/proxies/active` 的 `pools[].nodes` 按
`name` 关联；默认 `default-pool` 不在这个列表里（它是 `active=true` 的那个，
pattern 见 `active_proxy.pool_filter`）。

```json
[
  {
    "name": "ai-pool",
    "node_pattern": "momo/.*(香港|新加坡)",
    "size": 4,
    "per_terminal": true,
    "rule_sets": ["geosite-openai", "geosite-anthropic", "geosite-category-ai-!cn", "geosite-perplexity"],
    "rule_lists": [{"tag": "gemini", "url": "https://yfamilys.com/rule/Gemini.list"}],
    "domain_suffix": ["gemini.google.com", "generativelanguage.googleapis.com"]
  }
]
```

| 字段 | 说明 |
|---|---|
| `name` | 组名，与 `/api/proxies/active` 的 `pools[].tag` 对应 |
| `node_pattern` | Go RE2；空 = 继承全局 `data_plane.url_test.node_pattern` |
| `size` | 按 long-EWMA 取的 top-N；0 = 使用全局 K |
| `per_terminal` | 是否每终端固定出口（生成 `fb-<pool>-<ip>`） |
| `requires_passing` | 额外的站点探针门槛（可选） |
| `rule_sets` | 该分类 claim 的 geosite/geoip 标签 |
| `rule_lists` | 该分类 claim 的外部 classical 规则列表：`tag` 是 provider 名，也是 `<tag>.list` 文件名；`url` 只由 `scripts/stage.sh` 抓取 |
| `domain_suffix` | 该分类的精确域名（先于 rule_sets / whitelist 生效） |

---

## GET /api/pool/terminal

按 terminal IP 查询当前出口节点分配 + 各节点的健康数据。第三方对接、用户故障排查的主要入口。

```bash
curl -H "Authorization: Bearer ..." \
  "http://<node-ip>:18080/api/pool/terminal?ip=10.1.2.42"
```

```json
{
  "ip": "10.1.2.42",
  "subnet": "10.1.2.0/24",
  "in_subnet": true,
  "group_name": "fb-p-1a2b3c4d5e6f",
  "pool_mode": "auto",
  "active_node": "primary",
  "primary": {
    "name": "fishcloud/🇺🇸 美国01",
    "alive": true,
    "health": {
      "name": "fishcloud/🇺🇸 美国01",
      "rtt_p50_ms": 246,
      "rtt_p95_ms": 252,
      "jitter_ms": 6,
      "fail_rate": 0.0,
      "probe_count": 10,
      "qualified": true,
      "in_pool": true,
      "probes": {
        "openai-api":     {"ok": true,  "status_code": 401, "latency_ms": 224},
        "anthropic-api":  {"ok": true,  "status_code": 401, "latency_ms": 292},
        "api.github.com": {"ok": false, "status_code": 403, "last_error": "status Forbidden"}
      },
      "passive": {
        "active_conns": 3,
        "closed_window": 24,
        "failed_window": 1,
        "fail_rate": 0.04,
        "sample_window_sec": 600
      }
    }
  },
  "secondary": {
    "name": "ash/🇺🇸US-IEPL-02",
    "alive": true,
    "health": { "...": "..." }
  }
}
```

字段：
- `ip` — 入参 IP。回显方便日志。
- `subnet` — 节点配置的 `client_subnet`（如 `10.1.2.0/24`）。
- `in_subnet` — `false` 表示该 IP 不在 client_subnet，会走 `MATCH,default-pool` 兜底，**没有**专属的 per-terminal fallback 组。下面的 primary/secondary 字段缺省。
- `group_name` — mihomo 中对应的 fallback 组名（`fb-p-<pair-hash>` 形式；同一个 HRW [primary, secondary] 对共享一组，不再按 IP 一一命名）。可以直接用于 mihomo clash-api 调试。
- `pool_mode` — 当前 `node_qualify.pool_mode`。
- `active_node` — `primary` / `secondary` / `""`（都不可用）。系统按 mihomo fallback 语义判断：primary alive=true 时返回 primary，否则 secondary 替补。
- `primary.name` — HRW top-1 节点名。
- `primary.alive` — mihomo url-test 的最新探针结果。
- `primary.health` — 完整 NodeHealth 嵌入：rtt_p50/p95、jitter、fail_rate、probe_count、命名探针每个目标的最近一次状态、被动连接生命周期统计（`passive`）。
- `secondary.*` — 同 primary。另一家订阅有合格且存活的候选时，secondary 从**另一家订阅**的备用集合中按 HRW 选出（跨订阅备用，见 2026-10-27 变更）；否则退回同订阅 HRW top-2。当前实现固定每个 fb 组 2 个成员。
- `pools` — 仅列出 `per_terminal: true` 的分类池（如 `ai-pool`）。每项含
  `pool`、`group_name`（`fb-<pool>-p-<hash>`）、`primary` / `secondary` /
  `active_node`。顶层 `primary` / `secondary` 仍描述默认「其他」类；`pools`
  描述每个分类自己的稳定出口：

```json
"pools": [
  {
    "pool": "ai-pool",
    "group_name": "fb-ai-pool-p-6f5e4d3c2b1a",
    "active_node": "primary",
    "primary": {"name": "hutao/美国_BGP_E", "alive": true, "health": {"...": "..."}},
    "secondary": {"name": "momo/🇺🇸美国07_WD", "alive": true, "health": {"...": "..."}}
  }
]
```

错误：
- 400：`?ip=` 缺失。
- 503：scorer 未启用。
- 200 + `in_subnet: false`：传入了 client_subnet 之外的 IP，正常返回但没有 per-terminal 分配信息。

第三方对接建议：
- 用户报告"访问慢"时，先调一次此端点，立刻拿到 (primary, secondary) + 它们的 probe / passive 数据，足够判定问题来自机场端还是终端端。
- `active_node == ""` 表示这个 terminal 当前两个备份都不可用。配合 `/api/pool/state` 看 emergency 事件，决定是 hot-reload 还是手动改 yaml。
- HRW 是确定性的——同一 IP + 同一池成员永远同一答案。换池成员后，只有原本被分到被换节点的 terminal 会有新分配。

---

## GET /api/pool/transitions

返回池组成变更审计日志（K-gating 自动 swap、emergency evict/promote、operator rollback）+ 当前因 rollback 被隔离的节点列表。

```bash
curl -H "Authorization: Bearer ..." \
  "http://turnout-89:18080/api/pool/transitions?limit=20"
```

```json
{
  "transitions": [
    {
      "at": "2026-06-09T13:42:11Z",
      "type": "auto_swap",
      "added": ["fishcloud/🇺🇸 美国02"],
      "removed": ["ctc-02/US-C30-04-SNAP"],
      "pool_before": ["ash/...01", "ctc-02/04-SNAP", "..."],
      "pool_after": ["ash/...01", "fishcloud/02", "..."],
      "reason": "K-gating composite-score swap",
      "source": "scorer"
    },
    {
      "at": "2026-06-09T13:55:30Z",
      "type": "rollback",
      "added": ["ctc-02/US-C30-04-SNAP"],
      "removed": ["fishcloud/🇺🇸 美国02"],
      "reason": "operator rollback (1 step(s))",
      "source": "operator_api"
    }
  ],
  "quarantine": {
    "fishcloud/🇺🇸 美国02": "2026-06-09T14:55:30Z"
  }
}
```

字段：
- `transitions[].type`：`auto_swap`（K-gating 决策）/ `emergency_evict` / `emergency_swap`（emergency_promote_chain 顶替）/ `rollback`（操作员回滚）
- `transitions[].source`：`scorer`（系统）/ `operator_api`（API 调用）/ `operator_yaml`（yaml 编辑后 reconcile）
- `transitions[].added` / `removed`：相对前一状态的差集，按字典序
- `pool_before` / `pool_after`：完整快照
- `quarantine`：节点 → 隔离截止时间。被 rollback 移出的节点在隔离期内 K-gating 不会重新选中

`limit` 默认 50，最大 500。日志保留最近 200 条（capped），超出会被滚动覆盖。

503：scorer 未启用。

---

## POST /api/pool/rollback

回滚最近 N 次池变更，并把"刚被加入"的节点放进 rollback 隔离区。下一次 K-gating round 不会重新选中这些节点（直到隔离期满）——给操作员留排查 + 改 yaml + 决定是否延长隔离的时间窗口。

```bash
curl -X POST -H "Authorization: Bearer ..." -H "Content-Type: application/json" \
  -d '{"steps": 1, "quarantine_seconds": 3600}' \
  http://turnout-89:18080/api/pool/rollback
```

请求体（全部可选）：
- `steps`：回滚步数。默认 1，最大 = 当前 transitions 长度
- `quarantine_seconds`：被回滚节点的隔离时长。默认 3600 (1h)，最大 7×24×3600 (7d)

成功响应：
```json
{
  "steps_requested": 1,
  "steps_applied": 1,
  "reverted_transition_types": ["auto_swap"],
  "new_pool": ["ash/...01", "ash/...02", "ash/...03", "ctc-02/04-SNAP", ...],
  "quarantined": ["fishcloud/🇺🇸 美国02"],
  "quarantine_until": "2026-06-09T14:55:30Z"
}
```

失败：
- 400：`pool_mode=manual`（manual 模式应使用 `/api/pool/clear-emergency`）
- 400：JSON 格式错误

注意：
- 回滚自身也会被记入 transitions（type=`rollback`），但不可被进一步 rollback——避免回滚链条混乱
- 回滚后立刻触发 mihomo hot-reload，无需等下一个 5min scoring round
- 隔离期到期后，节点再次按正常 K-gating 评分；如果它仍是 top-K，会被重新选中。**隔离不是永久排除**——永久排除请改 yaml + redeploy
- 多次连续 rollback：每次回滚都是基于"当前 transitions 中最末一个非 rollback 项"，所以连续调用确实能往前再走一步

---

## 错误码

返回通知系统当前配置 + 健康状态。永远不返回 secret 本身（哪怕已配置），只返回 `secret_configured: true/false`。

```json
{
  "enabled": true,
  "webhook_configured": true,
  "signature_required": true,
  "secret_configured": true,
  "local_log_path": "/var/lib/turnout/notifications.log",
  "dedup_window_sec": 300,
  "aggregation_window_sec": 30,
  "per_node_rate_limit_per_hour": 4,
  "retry_attempts": 3
}
```

字段：
- `enabled` — `notifications.enabled` 开关
- `webhook_configured` / `signature_required` / `secret_configured` — Lark 子系统的可用性
- `dedup_window_sec` — 同 (node, event_type) 在窗口内合并为一条
- `aggregation_window_sec` — 多个 info 事件在窗口内打包成一条 Lark 消息
- `per_node_rate_limit_per_hour` — 单节点每小时最多 N 条 info 通知（urgent 不限）
- `retry_attempts` — webhook 失败时指数退避重试次数

---

## POST /api/notifications/lark

设置/更新 Lark webhook 配置。`webhook_url` 写入 `gateway.yaml` 的 `notifications.lark.webhook_url`；`secret` 写入独立文件（默认 `/var/lib/turnout/lark-secret`，0600 权限），yaml 不存 secret。

```bash
curl -X POST -H "Authorization: Bearer ..." -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://open.feishu.cn/open-apis/bot/v2/hook/xxx",
    "secret": "your-signing-secret",
    "signature_required": true
  }' \
  http://turnout-89:18080/api/notifications/lark
```

字段：
- `webhook_url`（必填）— Lark 自定义机器人 webhook URL
- `secret` — Lark 机器人的签名密钥；当 `signature_required=true` 时必填
- `signature_required`（可选，默认 `true`）— 启用 Lark HMAC-SHA256 签名校验。**生产强烈建议保持 true**——webhook URL 一旦泄露，没签名就能被任何人伪造消息

返回：post-config 的 `Status` body，同 `/api/notifications/status`。

副作用：
- yaml 持久化（webhook_url + signature_required，不含 secret）
- secret 文件原子写入（tmp + rename）
- Notifier 在线重建 Lark client，下一条事件就用新配置发

错误：
- 400 `webhook_url required` — 空 URL
- 400 `secret required when signature_required=true` — 缺 secret
- 500 — 持久化失败

---

## DELETE /api/notifications/lark

移除 Lark webhook 配置。secret 文件删除，yaml 中 `webhook_url` 清空。事件继续写到本地 JSONL 日志，**不再外发**——`notifications.enabled` 状态保持原样。

```bash
curl -X DELETE -H "Authorization: Bearer ..." \
  http://turnout-89:18080/api/notifications/lark
```

返回：post-deletion 的 `Status` body，可见 `webhook_configured: false`。

---

## POST /api/notifications/test

同步发一条测试消息。绕过 dedup / rate-limit / aggregation——一定尝试发送，便于操作员验证 webhook + secret 配置正确性。

```bash
curl -X POST -H "Authorization: Bearer ..." \
  http://turnout-89:18080/api/notifications/test
```

成功：
```json
{"ok": true}
```

失败（502 Bad Gateway）：
```json
{"ok": false, "error": "lark response not OK: {\"code\":19021,\"msg\":\"sign match fail or timestamp is not within one hour from current time\"}"}
```

错误信息会原样从 Lark API 透传过来，便于诊断签名错、URL 错、token 失效等问题。

---

## GET /api/notifications/recent

返回本地 JSONL 日志最近 N 条记录。即使 webhook 挂掉、Lark 不可达，记录也在；ops 通过这个端点可以重建"系统过去发生了什么"。

```bash
curl -H "Authorization: Bearer ..." \
  "http://turnout-89:18080/api/notifications/recent?limit=20"
```

```json
{
  "limit": 20,
  "entries": [
    {
      "at": "2026-06-09T13:42:11Z",
      "outcome": "delivered",
      "severity": "urgent",
      "type": "scorer_evict",
      "node": "fishcloud/🇺🇸 美国01",
      "subject": "pool member auto-evicted: fishcloud/🇺🇸 美国01",
      "body": "fail_rate >= 0.90 sustained 30m0s"
    },
    {
      "at": "2026-06-09T13:42:11Z",
      "outcome": "webhook_failed",
      "severity": "info",
      "type": "scorer_promote",
      "node": "fishcloud/🇺🇸 美国02",
      "subject": "promoted from chain: fishcloud/🇺🇸 美国02",
      "extra": {"err": "Post \"https://...\": dial tcp: lookup open.feishu.cn: no such host"}
    }
  ]
}
```

`outcome` 取值：
- `queued` — 进入 dispatcher 队列等待处理
- `delivered` — webhook 成功
- `webhook_failed` — 重试耗尽仍失败（保留 extra.err）
- `dropped_dedup_or_rate_limit` — 被 dedup 或 rate-limit 抑制
- `dropped_queue_full` — dispatcher 队列满（少见）
- `test_attempt` / `test_delivered` / `test_failed` — `/api/notifications/test` 触发

`limit` 默认 50，最大 1000。

---

## 错误码

| 状态 | 含义 |
|---|---|
| 400 | 请求体非法 / 字段格式错 / tag 不在 catalog |
| 401 | token 缺失或不匹配 |
| 404 | 资源不存在 |
| 409 | 资源冲突（订阅名重复） |
| 500 | 持久化 / 渲染 / reload 失败 |
| 502 | 按需拉取 .mrs 失败 |
| 503 | 功能未启用（NodeScorer 未激活） |

---

## 常用速查

```bash
BASE=http://<node-ip>:18080

# 状态
curl -s $BASE/api/status | jq .

# 节点评分（含 probe 结果）
curl -s $BASE/api/nodes/health | jq '{qualified, total, last_scored_at}'

# 当前 default-pool 成员（post Plan-A：通常 = 全部候选）
curl -s $BASE/api/nodes/health | jq '.nodes[] | select(.in_pool) | {name, rtt_p50_ms}'

# 哪些节点最近探针失败 (qualified=false ≠ 被踢出，pool 永远全员)
curl -s $BASE/api/nodes/health | jq '.nodes[] | select(.qualified|not) | {name, reason}'

# probe 结果：哪些节点能过 OpenAI
curl -s $BASE/api/nodes/health | jq '.nodes[] | {name, ok: .probes["openai-api"].ok}'

# 切 out → pin（手动指定出口）
curl -s -X POST -H 'Content-Type: application/json' $BASE/api/proxies/select \
  -d '{"selector":"out","name":"pin"}'
curl -s -X POST -H 'Content-Type: application/json' $BASE/api/proxies/select \
  -d '{"selector":"pin","name":"ctc-02/US-C30-01"}'

# 恢复 load-balance
curl -s -X POST -H 'Content-Type: application/json' $BASE/api/proxies/select \
  -d '{"selector":"out","name":"default-pool"}'

# 立即刷新订阅
curl -s -X POST $BASE/api/subscribe/refresh | jq .

# 追加 fake_ip_skip 内网域名
curl -s $BASE/api/whitelist \
  | jq '.fake_ip_skip += ["+.corp.example.com"]' \
  | curl -s -X PUT -H 'Content-Type: application/json' $BASE/api/whitelist -d @-
```

---

## 接入变更日志（前端 / 控制平台）

### 2026-10-29（走代理的 QUIC 回退 TCP）— 当前版本

**变更（数据面行为，非 breaking，无 API 字段变化）**：

- 走代理的 UDP 443（QUIC / HTTP/3）一律 REJECT，浏览器自动回退 TCP。直连
  （`geosite-cn` / 白名单外的 `MATCH,DIRECT`）不受影响，仍可用 QUIC。
- 原因：机场把 UDP 装在 TCP 隧道里转发（hutao 为 anytls），QUIC 自带的拥塞控制
  叠在上面会崩。10.100.6.15 实测（2026-10-29）同一终端、同一日本节点：YouTube
  视频流走 QUIC 持续 0.4–1.2 Mbps，走 TCP 83–89 Mbps；1080p 需要约 5 Mbps。
- 渲染形状：每个 sub-rule（`perterm`、`perterm-<pool>`）首行
  `AND,((NETWORK,UDP),(DST-PORT,443)),REJECT`；直接指向代理组的规则前面各有一条
  同条件的 `AND,((NETWORK,UDP),(DST-PORT,443),(<条件>)),REJECT`。

### 2026-10-28（egress 探测走线路池）

**修复（字段值变化，非 breaking）**：

- `/api/proxies/active` 的 `pools[].egress` 以前经 mixed-port（11080）探测，
  探测目标 ipinfo.io 要过规则表；whitelist 模式下它不在白名单，命中
  `MATCH,DIRECT`，显示的是公司直连出口（实测 AWS 俄勒冈），而默认类流量实际走
  日本/香港节点。现在经新增的 loopback 监听 `127.0.0.1:11082`（钉在 `out`，
  不查规则）探测，显示线路池真实出口。
- 新监听每次渲染都输出，只绑 127.0.0.1。

### 2026-10-27（跨订阅 secondary）

**变更（字段语义，非 breaking）**：

- 终端的 primary 不变（仍是路由池内 HRW top-1）。secondary 改为从**另一家订阅**
  中最好的 3 个合格且存活节点里按 HRW 选出；另一家没有可用节点时退回同订阅
  HRW top-2。`/api/pool/terminal` 的 `secondary` 与 `group_name` 随之变化。
- 原因：路由池 89% 时间只来自一家订阅，终端主备 99.4% 同订阅，三次机场入口事故
  里主备一起失效（24h 内 60 次代理失败中的 52 次）。跨订阅 secondary 让 mihomo
  的 fallback 在 5–30s 内把受影响终端切到另一家入口，不需要重载、不改变未受
  影响终端的出口 IP。
- 按订阅（tag 前缀）划分故障域，而不是 server 主机名：momo 的广州/上海主机名解析到
  同一 /23，hutao 单一主机名背后的 AWS 东京 IP 会轮换。
- `dns-out` 成员 = 路由池 + 默认类的跨订阅备用，DNS 不再只依赖一家入口。
- fallback 组数从 K(K−1) 降到约 K×3。

### 2026-10-23（per-terminal 组按节点对收敛 + 重载后 DNS 预热）

**变更（字段语义，非 breaking）**：

- `GET /api/pool/terminal` 的 `group_name` 从 `fb-<ip>` / `fb-<bucket>` 变为
  `fb-p-<pair-hash>`（分类池为 `fb-<pool>-p-<hash>`）。组不再按终端单元
  一一创建，而是按 HRW 的 [primary, secondary] **有序对**去重：/16 的 1024
  个桶只产生 K(K-1) 个组（8 节点 = 56），分类池同理。
- 分流语义不变：同一终端仍是同一个 [primary, secondary]，fallback 顺序
  不变；mihomo 的 alive 状态本来就挂在共享节点对象上。
- 影响：每次 `PUT /configs` 的健康检查拨号从 ~4096 降到 ~136，重载耗时
  从 6.1–7.5s 降到 ~0.6s（10.100.6.15 实测）。
- 新增 `data_plane.dns.preload_domains` + `preload_interval`；预热器在每次
  热重载成功后立即补查一轮（mihomo 每次 ApplyConfig 都会重建 DNS 解析器，
  缓存清零）。留空 = 关闭。

### 2026-10-17（旁挂角色改造）

**Breaking — 删除 1 个端点**：

| 端点 | 删除理由 |
|---|---|
| `GET /api/whitelist/resolved` | 它把 geosite/geoip 展开成扁平域名 + CIDR 列表，唯一消费者是上游控制台的"极速模式"。本仓库前端从未使用，数据面也不走它（渲染器直接 emit rule-providers 指向 `.mrs`，mihomo 自己加载）。随 `internal/whitelistexpand` 一并移除。 |

**Breaking — 字段改名**：

| 字段 | 变化 |
|---|---|
| `GET /api/proxies/active` 的 `feilian` | → `ingress`。旁挂角色下不存在 VPN 服务，原来的 `tun0_active` / `vpn_active` / `proxy_active` / `sentry_active` 四项永远是 false，属于噪音。新字段见下。 |

**新增字段**（`GET /api/proxies/active` → `ingress`）：

| 字段 | 说明 |
|---|---|
| `ingress.ingress_iface_up` | 引流网卡是否 up。为 false 时不会有任何流量到达——表现为"没人用"，而不是"坏了" |
| `ingress.ingress_ip_present` | `node.ingress_ip` 是否真的配在网卡上。缺失即防火墙的 PBR 下一跳已死 |
| `ingress.return_route` | 当前 IPv4 默认路由（字符串）。必须指向防火墙；为空表示回程不通 |
| `ingress.liveness_up` | watchdog 当前是否持有探活地址。判定不健康时为 false 是**预期**，不是故障 |

**新增端点**：

| 端点 | 说明 |
|---|---|
| `GET /api/watchdog/status` | 旁挂健康判定。**判定为 `unhealthy` 时返回 503，但仍带完整 body**（与 `/healthz` 同构）。`state=unknown` 表示首轮自检尚未完成，属正常启动态，返回 200。 |

```json
{
  "state": "healthy",
  "at": "2026-10-17T09:00:10Z",
  "checks": [
    {"name": "engine_alive",    "ok": true,  "detail": "clash-api 127.0.0.1:9090 answering"},
    {"name": "dataplane_rules", "ok": true,  "detail": "all 4 data-path checks passing (asserted 12s ago)"},
    {"name": "pool_healthy",    "ok": true,  "detail": "7 alive / 19 total (need 1)"}
  ],
  "failing": [],
  "fail_streak": 0,
  "ok_streak": 12,
  "fail_threshold": 3,
  "recover_threshold": 3,
  "liveness_ip": "10.255.255.3",
  "liveness_up": true,
  "auto_failover": false,
  "last_transition": "2026-10-17T08:41:02Z"
}
```

> `auto_failover=false` 时，`state=unhealthy` 表示**已经告警但尚未切回**——防火墙仍在引流，
> 需要人工处理。控制台必须把这一点显式渲染出来，否则红色判定很容易被读成"已自动处理"。

### 2026-07-04（active 接口运维增强）

**Breaking**：

| 字段 | 变化 |
|---|---|
| `active_proxy.active_urltest` | → `active_proxy.active_group`（语义更准确，原字段删除） |
| `active_proxy.history_len` | **已删除**（无运维价值） |
| `pools[].pool_size` | 语义变更：原为 mihomo `all` 全量大小，现为 routing pool（top-K）实际大小 |
| `pools[].nodes[]` | 语义变更：原返回全量 default-pool 成员，现只返回 routing pool 成员（scorer 不活跃时降级为全量） |

**新增字段**：

| 字段 | 说明 |
|---|---|
| `active_proxy.pool_mode` | `"auto"` / `"manual"`，决定运维操作方向 |
| `active_proxy.last_swap_at` | 池成员最近一次变更时间（RFC3339） |
| `pools[].nodes[].fail_rate` | NodeScorer 探针失败率（0.0–1.0）；scorer 不可用时为 -1 |

### 2026-06-10（清理 manual 模式遗留）— 当前版本

**Breaking — 删除 3 个端点**：

| 端点 | 删除理由 |
|---|---|
| `GET /api/geosites` | 与 `/api/rule-sets` 同数据，纯遗留兼容别名 |
| `GET /api/pool/state` | 只在 `pool_mode: manual` 下有意义；auto 模式下输出是 stale 数据 |
| `POST /api/pool/clear-emergency` | 同上，manual 专用；auto 下应该用 `/api/pool/rollback` |

替代查询（auto 模式）：
- 当前池成员 → `/api/nodes/health` 过滤 `in_pool: true`
- 池规模 K → `/api/status.pool_sizing`
- 池历史变更 → `/api/pool/transitions`

### 2026-06-09 深夜（B+ v2 — EWMA + trial + 稳定度）

**评分系统升级**（影响 auto 模式池决策，REST 表面新增字段）：

- `pool_mode: auto` 的池决策不再基于"当前轮单次 compositeScore"，而是基于双窗 EWMA：
  - **短窗（4h 半衰期）** — 驱动 evict 决策。新出现的降级在 ~2 小时内反映到分数。
  - **长窗（24h 半衰期）** — 驱动 promote 决策。"刚恢复"的节点要等长窗忘掉旧坏期才会被晋升，避免抖动。
- **24h trial 窗口**：新订阅引入的节点在 24h 内不被 EWMA-promote 路径选中（除非已在池中或 emergency 路径触发）。
- **绝对交换阈值** `swap_threshold_score`（默认 100）：候选要晋升必须比池内最差成员的长窗 EWMA 好 ≥ 100 分。降到 0 = 任何改进都换。
- **池稳定度 24h** — `/api/status` 新增 `pool_stability_24h` 字段：

```json
"pool_stability_24h": {
  "window_hours":     24,
  "swap_count":       2,
  "rollback_count":   0,
  "unique_nodes_in":  3,
  "unique_nodes_out": 3,
  "oldest_at":        "2026-06-09T01:13:00Z"
}
```

ops 看一眼这个就知道"系统过去一天动了多少"。频繁高 swap_count 是 thrashing 信号；持续 0 是池稳定。

**配置默认变化**（向后兼容，原有 yaml 不需要改）：

```yaml
node_qualify:
  swap_threshold_score: 100   # 默认 100；写 0 回退到旧"top-K 直接换"
```

**状态文件 v3 schema 兼容扩展**（增加 `ewma` 字段）。v1/v2 文件自动升级，无操作。

### 2026-06-09 夜（池审计 + 回滚）

**新增端点**（B+ issue 6 闭环）：

| 端点 | 用途 |
|---|---|
| `GET /api/pool/transitions` | 池变更审计日志 + 当前隔离名单 |
| `POST /api/pool/rollback` | 回滚最近 N 次变更，隔离被回滚的节点 |

**机制**：
- 每次池组成变化（auto K-gating swap / emergency evict-promote / 操作员 rollback）都记入 transitions（capped 200 条），含 type / added / removed / pool_before / pool_after / reason / source
- `rollback` 反向执行 transitions（重新加回被移除的节点，移除被加入的节点），并把刚被移除的节点放进 quarantine
- quarantine 期间（默认 1h，可配 ≤7d），K-gating 选 top-K 时跳过这些节点——避免回滚被立即覆盖
- 状态 file 升级 v2 → v3（自动兼容旧 v1/v2 文件）

### 2026-06-09 晚（Lark 通知）

**新增端点**（Lark 通知 + 池审计预备）：

| 端点 | 用途 |
|---|---|
| `GET /api/notifications/status` | 通知系统配置 |
| `POST /api/notifications/lark` | 设置 webhook url + secret（HMAC 签名） |
| `DELETE /api/notifications/lark` | 移除 webhook |
| `POST /api/notifications/test` | 同步测试发送 |
| `GET /api/notifications/recent` | 本地 JSONL 日志最近 N 条 |

**通知机制**：
- 严重档：紧急 (urgent，绕过 dedup/限速)、信息 (info)、完成 (done)
- dedup：5min 内同 (node, type) 合并；info 单节点每小时最多 4 条；urgent 不限
- aggregation：30s 内多事件合并为一条 Lark 消息（urgent 不参与）
- 重试：失败时指数退避 1s/2s/4s，3 次后落本地日志
- 安全：默认 HMAC-SHA256 签名，secret 持久化在 0600 权限文件，yaml 不存 secret

**配置关键字段**（`notifications:` 块）：
```yaml
notifications:
  enabled: true
  lark:
    webhook_url: ""             # 通过 API 设置
    signature_required: true    # 默认 true，强烈推荐
    secret_file: /var/lib/turnout/lark-secret
  local_log_path: /var/lib/turnout/notifications.log
  dedup_window: 5m
  aggregation_window: 30s
  per_node_rate_limit_per_hour: 4
  retry_attempts: 3
```

### 2026-06-09 上午（commit `49ece0e`+）

**新增端点**（手动池管理 + 终端查询）：

| 端点 | 用途 |
|---|---|
| `GET /api/pool/state` | 手动池 yaml baseline / effective / emergency 事件日志 |
| `POST /api/pool/clear-emergency` | 还原 effective 池到 yaml baseline |
| `GET /api/pool/terminal?ip=X` | 按 terminal IP 查出口节点 + 各节点健康 |

**架构变化**（影响 mihomo 配置形态，REST 表面不变以下端点）：

- 默认池模式从"K-gating auto"切到"manual"——`pool_mode: manual` + 操作员维护 `pool_members:` 列表。详见 `node_qualify.pool_mode` 配置。
- `mihomo` 的 perterm sub-rule 现在指向 `fb-<ip>` fallback group，每组含 HRW 选出的 [primary, secondary]。节点死了 mihomo 自动切到 secondary（30s 内），不再依赖 turnout-gateway 30min 等待。
- 已删除 `perterm-<poolname>` 子规则——同一 terminal 的所有目的地走同一 egress（CF 反检测要求）。pool_members 选节点时需自行确认 OpenAI 兼容性。

### 2026-06-06（commit `21a88d5`）

**Breaking**：

| 端点 / 路径 | 变化 |
|---|---|
| `POST /api/ux/event`、`GET /api/ux/events`、`GET /api/ux/stats` | **已删除**（commit `9bb5ee9`，整个 ux-telemetry 子系统下线，前端勿再上报） |

**配置相关（影响部署，但 REST 表面不变）**：

- `data_plane.tproxy_port` 现在是**全局必填**（>0）。`--validate` 会拒绝 `tproxy_port: 0`，TUN-only 模式不再支持（之前只在 `load_balance.per_terminal=true` 时强制）。
- 部署链增加 `--validate`：`mihomo -t` 在临时目录跑，永远不写生产 `config.yaml`。
- install.sh 增加 `--print-env` 生成 `/etc/turnout/env`，nft 模板和 `iproute.sh` 都从这里读，不再 grep YAML。

### 2026-06-06（commit `0d7432d`）

**新增字段**：

| 端点 | 字段 | 说明 |
|---|---|---|
| `/api/nodes/health` | `probes`（顶级 + 节点级） | site-specific probe 结果；`cf_mitigated` 检测 CF challenge；`latency_ms` 失败时为真实等待时长 |
| `/api/nodes/health` | `nodes[].passive` | 被动连接统计：`active_conns / closed_window / failed_window / fail_rate / sample_window_sec` |
| `/api/status` | `capacity`（条件返回） | 压测天花板：`sustained/degraded_max_users / measured_at / measured_with` |

**Breaking（上轮已通知）**：

| 字段 | 变化 |
|---|---|
| `singbox_ok` | → `engine_ok` |
| `turnout.singbox_version` | → `turnout.engine_version` + 新增 `turnout.engine`（恒为 `"mihomo"`） |
| `active_proxy.watchdog` | **已删除** |
| `turnout.services` 中的 sing-box 条目 | **不再返回**（services 只剩 gateway/mihomo/nft） |

**约定**：
- 字段命名 `snake_case`；时间戳 RFC3339；数值后缀标单位（`_ms` / `_sec` / `_bps`）
- 可选字段缺失时不返回（用 `?.` / nullish 处理）
- breaking change 一律在此节记录
