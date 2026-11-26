# 跨境访问日志：方案

状态：已实现（`internal/xborder`），传输定为 Syslog TCP；未部署，待填日志服务器地址（2026-11-25）。
字段可得性均在线上节点只读实测（mihomo 1.19.26）。示例数据均为虚构。

## 1. 记录范围

- 记录：终端发起（`type=TProxy`）、实际出口 `chains[0]` 不是 `DIRECT` / `REJECT` /
  `REJECT-DROP` / `PASS` 的连接，以及经海外节点的拨号失败。
- 不记录：国内直连、广告/成人拦截、网关自身连接。实测 `type=Inner` 全部是
  `specialProxy=dns-out`（网关经节点发出的 DoH 查询），没有终端 IP，不是终端访问。

## 2. 字段（最终）

| 分类 | 字段 | 来源 | 说明 |
|---|---|---|---|
| 事件 | `schema` `event` `ts` `seq` | 本进程 | `seq` 跳号只能发现发送队列的丢弃 |
| 网关 | `gateway.hostname` | 本机 | |
| 会话 | `conn.id` `network` `start` | `/connections` | 短连接无 ID 时合成：`log-<源ip>-<源端口>-<毫秒>` |
| 会话 | `conn.end` `duration_ms` | 从快照消失的时刻 | 误差约 1 个采样周期 |
| 终端 | `src.ip` `src.port` | `/connections` | 审计主键 |
| 目标 | `dst.host` `dst.sniff_host` `dst.port` | `/connections` | `sniff_host` 空 = 未嗅探到 |
| 目标 | `dst.ip` | `/connections` 的 `destinationIP`；为空时跑一次 `ss -tn`，按终端 ip:port 找 TPROXY 套接字的本地地址 | 终端**原本要连**的 IP，不是机场节点最终连接的 IP；仅 TCP |
| 路由 | `rule` `rule_payload` `pool` `group` `chains` | `/connections` + 配置 | |
| 出口 | `egress.node` | `chains[0]` | 拨号失败时为空，见 §4 |
| 出口 | `egress.region` | 由节点名推断 | 推不出为空 |
| 流量 | `up_bytes` `down_bytes` `bytes_final` | 最后一次采样 | `bytes_final=false` 表示结尾可能漏计 |
| 结果 | `result.status` `result.error` | `ok` / `dial_error`；错误原文来自 mihomo warning | |
| 采集 | `collect.tracked` `collect.logged` | 是否出现在 `/connections` / 日志流 | 判断这条记录完整到什么程度 |

不写入：订阅 URL、节点密码/UUID、API token。

拿不到：URL 路径与内容、进程名、海外侧实际连接的 IP、用户名/主机名/MAC
（后者需对接 DHCP/AD/防火墙，本期不做）。

## 3. 采集

| 来源 | 作用 |
|---|---|
| `/logs?level=info`（HTTP 流） | 拨号失败只出现在这里；补上采样漏掉的短连接 |
| `/connections`，每 1s | ID、字节、链路、起止 |
| `ss -tn`，按需：只在新出现的 TCP 连接缺 `destinationIP` 时跑 | `dst.ip` |

三者按 `network + 源IP:源端口 + 时间窗` 关联。

## 4. 事件

| 事件 | 时机 |
|---|---|
| `close` | 连接结束，一条连接一条 |
| `dial_error` | 拨号失败。mihomo 的 warning 只给出代理组名，不给节点名，`egress.node` 为空，节点服务器地址在 `result.error` 原文里 |

gateway 重启不会丢失进行中连接的 `close`：`conn.id`、`start` 与累计字节都由 mihomo 保存，
重启后的进程重新看到该连接，结束时照常输出。丢失的只是在 gateway 停机期间结束的连接。

## 5. 发送

RFC 5424 over TCP，每条消息体是一行 JSON：

```
<174>1 2026-11-24T10:01:30.500123+08:00 <主机名> turnout-xborder <pid> close - {"schema":"turnout.xborder.v1",...}
```

- PRI：facility 默认 local5；`close` 为 info（174），`dial_error` 为 warning（172）。MSGID 即事件名。
- 分帧：默认 `lf`（每条一行，JSON 内不含裸换行）；接收端要求时可选 `octet-counting`（RFC 6587）。
- 发送不阻塞转发；内存队列 1 万条（按约 700 条/小时，可扛约 14 小时断线），满了丢最旧的，
  每分钟在 gateway 日志里报一次丢弃数。服务器断线后按 1s→30s 退避重连，队列按序补发。
- 每次写之前检查对端是否已关闭连接，避免服务器重启后第一条记录写进死连接。
  但纯 TCP 没有确认：服务器在收下数据前崩溃仍可能丢，接收端表现为 `seq` 跳号。
- 日志含员工访问记录，传输未加密；留存期与访问权限待确认。

配置（`gateway.yaml`，模板见 `configs/gateway.example.yaml`）：

```yaml
xborder_log:
  enabled: true
  address: "<日志服务器>:514"
  # 以下为默认值，可省略
  framing: lf
  facility: local5
  app_name: turnout-xborder
  poll_interval: 1s
  queue_size: 10000
```

启用时校验：缺 address、`data_plane.log_level` 高于 info（短连接与拨号失败只在 info 日志里）
都会拒绝启动。修改后需重启 turnout-gateway。

量级：约 700 条/小时，每条约 0.9 KB（按试跑中的一条样本估），约 15 MB/天。

## 6. 示例（虚构）

```json
{"schema":"turnout.xborder.v1","event":"close","seq":1024,"ts":"2026-11-24T10:01:30.500+08:00",
 "gateway":{"hostname":"gw-example"},
 "conn":{"id":"00000000-0000-0000-0000-000000000000","network":"tcp","start":"2026-11-24T10:00:00.000+08:00","end":"2026-11-24T10:01:30.500+08:00","duration_ms":90500},
 "src":{"ip":"198.51.100.20","port":50000},
 "dst":{"host":"www.example.com","sniff_host":"www.example.com","ip":"203.0.113.5","port":443},
 "route":{"rule":"SubRules","rule_payload":"(RULE-SET,geosite-example)","pool":"example","group":"fb-example","chains":["sub-a/node-1","fb-example"]},
 "egress":{"node":"sub-a/node-1","region":"US"},
 "traffic":{"up_bytes":4600,"down_bytes":3000,"bytes_final":false},
 "result":{"status":"ok","error":""},
 "collect":{"tracked":true,"logged":true}}
```

## 7. 线上试跑（2026-11-25，只读）

临时程序接线上 mihomo 跑 5 分钟（不经生产服务），与同时段 mihomo journal 逐条对账：

| 项 | 数 |
|---|---|
| journal 中跨境连接行 | 40（拨号失败 0） |
| 已出记录 | 33 |
| 结束时仍未关闭（关闭时才出，属设计） | 7 |
| **漏记** | **0** |
| 只在日志流里出现（两次采样之间就关闭，无字节数） | 9 / 33 |
| 采样到但没对上日志行 | 5，全是试跑开始前已建立的连接 |

另跑 3 分钟经本机临时 TCP 监听走完整发送链路：12 条全部送达、解析，无坏帧、无丢弃。

结论：日志流不可省——约 1/4 的跨境连接存活不到一个采样周期，只能靠它记下来，
但这些记录没有字节数。拨号失败路径只有单元测试（用的是线上真实格式的日志行），
试跑窗口内没有出现，**未在线上验证**。

## 8. 交叉评审记录（2026-11-24）

**删除**

| 条目 | 依据 |
|---|---|
| `quality.client_rtt_ms` | 实测 p50 4.45 ms、最大 14 ms：测的是办公网到网关这一段，反映不了跨境慢 |
| `dst.country` | 机场节点会重新解析域名，`dst.ip` 不是实际到达的服务器，国家只是"终端本来想连的 IP"的国家；本机 `geoip.metadb` 为 `Meta-geoip0` 格式，要新增依赖或自写解码器 |
| `egress.server_ip`（`remoteDestination`） | 含义未证实：5 条连接的 `remoteDestination` 0 条落在本机解析出的节点服务器 IP 集合中（20 个 server，29 个 IP）。审计日志里放含义不明的 IP 会被误读为目标 |
| `update` 事件 | 理由"长连接可见、防重启丢失"不成立：重启不丢（§4）；实测 6 条存活连接中 1 条超过 5 分钟、0 条超过 1 小时 |
| `open` 事件 | 默认关闭、无人提出需求 |
| 磁盘缓冲 | 内存 1 万条已可扛约 14 小时断线 |
| `type=Inner` 记录 | 全是 dns-out，不是终端访问 |
| `src.terminal_group` | 与 `route.group`（chains 最后一跳）重复 |
| `dst.host_source` `app_proto` `egress.subscription` | 都能从同一条记录的其他字段推出 |
| `egress.protocol`、节点 RTT/失败率 | 节点静态属性或节点级统计，不属于这条连接；`/api/proxies` 可查 |
| `gateway.ip` `version` `engine_version`、`collect.polls` | 只有一台网关；版本可按部署时间对应；`polls` 无使用场景 |

**未验证**

- `/logs` 流在消费慢或断线重连时会不会丢行；丢了就缺短连接与拨号失败记录。
- UDP/QUIC 出墙：样本全是 TCP，UDP 下 `dst.ip` 只能取 mihomo 的 `destinationIP`，未验证。
- 采样漏掉的短连接比例：已由 §7 试跑测得约 1/4。
- `ss` 未匹配到的 5/26 条原因未查。
