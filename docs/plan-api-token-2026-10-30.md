# 管理 API 加固：HTTPS 自签证书 + 强制 token（前端生成、人工确认生效）（2026-10-30）

状态：方案，未实施。

## 0. 背景与目标

- 现状：nft `chain input` 最后一条对所有来源放行 18080（2026-10-22 起办公网被引流终端也能访问）；
  `api.token` 可选，为空时 `s.auth` 直接放行（`internal/api/api.go:212`）；整个控制面是明文 HTTP。
  任何内网主机都能改订阅、白名单、出口选择；即使配了 token，同网段也能嗅探到。
- 目标：**保持 18080 对整个内网开放**，同时
  1. 18080 只说 HTTPS，证书由节点自签（第 1 部分）；
  2. 所有 `/api/*`（`/healthz` 除外）必须带 token。token 由前端浏览器生成，操作者点击确认后
     才在服务端生效（第 2 部分）。
- 两部分**同一版本上线**：初始化时要提交 setup code，没有 TLS 它会以明文在内网传输。
- 非目标：多账号 / 角色、订阅 URL 的 SSRF 过滤、mihomo 的 9090 controller（只绑 127.0.0.1，不改）。

---

# 第 1 部分：HTTPS 自签证书

## 1.1 关键设计决定

1. **同一端口 18080 改为 TLS**，不另开端口：书签、nft 规则、`api.listen` 都不用变。
   明文请求打到 18080 时不处理业务（见 1.4）。
2. **节点启动时自动生成证书**，私钥长期不变，证书按年续期。所有程序化调用方都**钉公钥**
   （SPKI SHA-256），而不是钉证书：续期、改 IP 重签都不换私钥，钉住的值不变。
3. **浏览器走 TOFU**：首次访问点"继续前往"，访问前对照带外渠道（SSH、飞书）拿到的证书指纹。
   页面上不显示指纹 —— 被中间人时页面本身也是假的，在页面上核对没有意义。
4. **运维可以换成自有证书**（如公司内部 CA 签发），此时关闭自动生成和续期。

## 1.2 证书参数

| 项 | 取值 | 原因 |
|---|---|---|
| 密钥 | ECDSA P-256 | 体积小，所有浏览器和 curl 支持 |
| 有效期 | 397 天 | macOS 对 TLS 证书有 825 天上限，Chrome 对公共证书 398 天；取 397 天，导入系统信任时也不被拒 |
| SAN | `127.0.0.1`、`::1`、`node.ingress_ip`、本机所有非回环 IPv4、主机名，以及 `api.tls.extra_sans` | 让 `--cacert` 和导入信任的浏览器在常见访问方式下都不报名称错误；NAT / DNS 名靠 `extra_sans` 补 |
| 扩展 | `ExtKeyUsage=serverAuth`，`BasicConstraints CA:false` | 只能当服务端证书，导入信任后也不能拿来签别的站点 |
| 最低 TLS 版本 | 1.2 | Go 默认套件 |
| 文件 | `/var/lib/turnout/api-tls/key.pem`（0600）、`cert.pem`（0644） | 与 token 文件同目录树，`install.sh` 不覆盖，`make redeploy` 保留 |

## 1.3 生命周期

- **首次启动**：没有 key 就生成 key + 证书，journal 打印证书 SHA-256 指纹和 SPKI pin（都是公开信息，
  可以打印）。
- **续期**：每天检查一次，到期前 30 天用**同一把私钥**重签。`tls.Config.GetCertificate` 从
  `atomic.Pointer` 读当前证书，热替换，不重启。续期后发飞书通知，带新的证书指纹（浏览器里要
  重新确认一次），并说明 SPKI pin 不变。
- **SAN 变化**：启动时以及 `PUT /api/node/network` 之后，若算出的 SAN 集合和当前证书不同，用同一把
  私钥重签并热替换。
- **换密钥**（怀疑私钥泄露）：`turnout-gateway --rotate-tls-key` 删除 key 和证书，重启后重新生成。
  所有调用方的 pin 都要更新，见 1.6。
- **自有证书**：配置了 `api.tls.cert_file` / `key_file` 指向非默认路径时，只加载、不生成不续期；
  文件变化后重启生效；到期前 30 天起每天发一次飞书告警。

## 1.4 明文请求的处理

在 listener 层偷看连接的第一个字节：`0x16`（TLS 握手）交给 `tls.Server`，其他视为明文 HTTP，交给一个
只做两件事的处理器：

- `GET` / `HEAD`：`308` 跳到 `https://<Host>/<原路径>`，旧书签 `http://node:18080/ui/` 继续能用。
- 其他方法：`400`，正文提示"改用 https；如果这个请求带了 token，请轮换 token"。
  不做跳转：带 Bearer 的请求一旦以明文发出，token 已经泄露，跳转只会掩盖问题。

不发 HSTS：浏览器对 IP 地址和证书有错误的站点都会忽略 HSTS。

## 1.5 配置

```yaml
api:
  listen: "0.0.0.0:18080"
  tls:
    enabled: true                 # 默认 true
    cert_file: ""                 # 留空 = /var/lib/turnout/api-tls/cert.pem，自动生成并续期
    key_file: ""                  # 留空 = /var/lib/turnout/api-tls/key.pem
    extra_sans: []                # 额外的 IP / DNS 名，例如经 NAT 访问时的地址
```

- `enabled: false` 只允许在 `listen` 为回环地址时使用，否则 `config.Load` 报错拒绝启动。
- `--print-env` 输出 `TURNOUT_API_SCHEME=https` 和证书路径，给 `iproute.sh` / 脚本用。
- 新增 `turnout-gateway --tls-info`：打印证书指纹、SPKI pin、SAN、到期时间。

## 1.6 调用方改造

| 调用方 | 现状 | 改为 |
|---|---|---|
| 浏览器 `/ui/` | `http://node:18080/ui/` | `https://...`，明文访问会自动 308 跳转 |
| `turnout-healthwatch` | `--api http://127.0.0.1:18080` | 默认 `https://127.0.0.1:18080`，新增 `--api-tls-pin`，默认从证书文件计算 SPKI pin，用 `VerifyPeerCertificate` 校验公钥 |
| 节点上的脚本：`observe.sh`、`verify-bypass.sh`、`redeploy-full.sh` 里在节点执行的 curl | `http://127.0.0.1:18080` | `https://127.0.0.1:18080` + `--cacert /var/lib/turnout/api-tls/cert.pem`（每次运行都现读文件，续期不影响） |
| `scripts/pool-monitor.py` | `http://127.0.0.1:18080` | `https://` + `ssl.create_default_context(cafile=cert.pem)` |
| `Makefile`（笔记本 → 节点） | `TURNOUT_API ?= http://$(NODE_HOST):18080` | `https://...`；新增 `TURNOUT_PIN`，未设置时经 SSH 读节点证书算出 pin，缓存到 `.turnout/<host>.pin`（加入 `.gitignore`）；curl 用 `--pinnedpubkey sha256//<pin>`，不依赖 SAN |
| `scripts/deploy.sh`（笔记本 → 节点） | `http://$HOST:18080` | 同 Makefile：先经 SSH 取 pin，再 `--pinnedpubkey` |
| `web/vite.config.ts` dev 代理 | `LEAP_API` 默认 `http://127.0.0.1:18080` | 默认 `https://`，代理加 `secure: false`（经 `ssh -L` 隧道，链路已由 SSH 保护） |
| `docs/api.md`、`configs/gateway.example.yaml` | http 示例 | 改为 https，补充 pin / cacert 用法 |

已实测（2026-10-30，macOS curl 8.7.1 / OpenSSL 3.6）：`-k` 打开时 curl 仍校验 pin，pin 不匹配时以
exit 90 中止；OpenSSL 3 接受这张 `CA:false` 自签证书作为 `--cacert` 信任锚（含 `-x509_strict`）。

---

# 第 2 部分：强制 token，前端生成、人工确认

## 2.1 关键设计决定

1. **去掉"无 token 即开放"模式。** 没有 token 时进入 `setup` 状态：除初始化接口外，所有
   `/api/*` 返回 401 `setup_required`，而不是放行。
2. **"点击确认"之外还要一个 setup code。** 只靠点击，内网里谁先打开页面谁就能抢先设 token
   （初始化抢占）。确认时必须同时提交一次性 setup code，证明操作者能登录节点或能看到运维飞书群。
   这是整个方案的安全前提，不能省。
3. **token 存在节点本地文件，不写进 gateway.yaml。** `make redeploy` 会把节点上的 yaml 拉回笔记本，
   放进 yaml 就会离开节点。沿用飞书签名密钥的做法（`notifications.lark.secret_file`，0600）。
4. **token 由浏览器 `crypto.getRandomValues` 生成**，服务端只校验格式，不信任也不改写。

## 2.2 状态机

```
            启动时无 token 文件且 yaml 无 api.token
  ┌────────────────────────────────────────────────┐
  │                                                ▼
  │   ┌──────────┐  POST /api/auth/setup        ┌──────────┐
  │   │  setup   │ ───(token + setup code)────▶ │  active  │ ◀─┐
  │   └──────────┘                              └──────────┘   │ POST /api/auth/rotate
  │        ▲                                          │        │ (带当前 token)
  │        │   turnout-gateway --reset-api-token      └────────┘
  │        └───────────── + 重启服务 ─────────────────┘
```

- `setup`：进入时生成 setup code，写入 `/var/lib/turnout/api-setup-code`（0600，root），文件里
  **同时写上当前证书的 SHA-256 指纹**，操作者一次 `sudo cat` 就拿到初始化所需的两样东西。journal
  只打印"setup code 在某某文件"，不打印 code 本身。已配置飞书时额外推送 code + 指纹到群里。
  code 为 100 bit 随机数，base32 分组显示（`XXXX-XXXX-XXXX-XXXX-XXXX`），每次进程启动重新生成。
- `active`：`s.auth` 用 `subtle.ConstantTimeCompare` 校验 Bearer。token 放在 `atomic.Pointer`
  里，每个请求读一次（现在的实现在注册路由时就把 token 捕获进闭包了，这一点必须改）。
- token 来源优先级：token 文件 > yaml `api.token`（旧节点兼容）> 都没有 → `setup`。
  setup / rotate / reset 都会顺手清空 yaml 里的 `api.token`（经 `configstore.Mutate`），
  避免以后删了文件又"复活"一个旧 token。

## 2.3 接口

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/api/auth/state` | 无 | `{"state":"setup"\|"active","setup_code_hint":"/var/lib/turnout/api-setup-code","lark_delivered":bool}`，不含任何秘密 |
| POST | `/api/auth/setup` | setup code | body `{"token","setup_code"}`；仅 `setup` 状态可用，否则 409。成功后原子写 token 文件、删 setup code 文件、切换内存 token |
| POST | `/api/auth/rotate` | 当前 token | body `{"token"}`；旧 token 立即失效（不设宽限期） |
| GET | `/api/auth/check` | 当前 token | 204，前端登录探测用（取代现在用 `/api/status` 探测） |

约束：

- token 格式 `^tgw_[A-Za-z0-9_-]{43}$`（32 字节 base64url + 前缀，前缀方便密钥扫描工具识别）。
- setup code 比较用常量时间；setup 走互斥锁，同一时刻只有一个请求能完成初始化。
- body 用 `http.MaxBytesReader` 限 4 KiB。
- 没有 CORS 头，跨站页面读不到响应，Bearer 也不会被浏览器自动带上，不需要额外的 CSRF 防护。
- 鉴权失败记日志（来源 IP + 路径）。同一 IP 10 分钟内失败 ≥5 次时发一条飞书告警，用 dispatcher
  现有的去重，不做封禁：token 和 setup code 都有 ≥100 bit 熵，限速挡不住什么，告警的价值在于
  发现有人在试。
- setup 成功、rotate、reset 各发一条飞书通知（含来源 IP），方便事后审计。

## 2.4 前端流程（`web/src`）

`Login.tsx` 挂载时先调 `GET /api/auth/state`：

**`setup` → 显示"初始化控制台"页**

0. 页首提示：**先核对证书指纹**（浏览器地址栏 → 证书详情 → SHA-256），与 `sudo cat
   /var/lib/turnout/api-setup-code` 或飞书消息里的指纹一致再继续；不一致说明连接被劫持，不要提交。
1. 页面加载即生成 token，只读输入框显示，带"复制"和"重新生成"按钮。复制优先用 Clipboard API，
   不可用时（例如浏览器对证书报错的页面不算安全上下文）回退到选中文本 + `document.execCommand('copy')`。
2. 勾选框"我已把 token 保存到密码管理器"，不勾选时确认按钮置灰。
3. 输入框"setup code"，提示文案写清楚去哪拿：
   `ssh 节点后执行 sudo cat /var/lib/turnout/api-setup-code`；若 `lark_delivered` 为真，再加一句
   "或查看运维飞书群"。
4. 点"确认启用"→ `POST /api/auth/setup` → 成功后直接用这个 token `connect()` 进入控制台，
   并弹一次提示：本机脚本 / Makefile 需要 `export TURNOUT_TOKEN=...`。
5. 折叠的"使用已有 token"：允许粘贴一个 `tgw_` token 代替生成值，用于多节点共用一个 token。
   默认推荐每个节点独立 token。

**`active` → 现有登录页**，token 改为必填，删掉"若 `api.token` 为空可留空"的文案；控制面地址的
默认值和 placeholder 改为 `https://<node-ip>:18080`。

**轮换**：Network 页（或新加"安全"卡片）放"轮换 token"，复用同一个生成 + 勾选确认组件，调
`/api/auth/rotate`，成功后当前标签页无缝换成新 token，其他已打开的标签页会收到 401 并回到登录页。
同一张卡片显示证书到期时间和 SAN（不显示指纹，理由见 1.1 第 3 条）。

token 仍只放内存，不进 web storage（`api.ts` 现有约束不变）。

## 2.5 节点侧与脚本

- 新增 `api.token_file`，默认 `/var/lib/turnout/api-token`（0600，root）。`install.sh` 只建目录，
  不碰这个文件，所以 `make redeploy` 会保留 token。
- `turnout-gateway --reset-api-token`：删 token 文件、清空 yaml `api.token`，然后提示重启服务。
  `Makefile` 加 `make reset-token NODE=...` 包一层。这是忘记 token 时唯一的恢复路径，需要 SSH 权限，
  这也是故意的。
- `turnout-healthwatch` 增加 `--api-token-file`，默认读同一个文件；收到 401 时重读一次（适配轮换）。
  保留 `HEALTHWATCH_API_TOKEN` 作为覆盖。
- 节点上执行的脚本（`redeploy-full.sh`、`verify-bypass.sh`、`observe.sh`）在未设置 `TURNOUT_TOKEN`
  时改为从节点上 `sudo cat` token 文件。从笔记本直连节点 API 的 Makefile 目标和 `deploy.sh` 仍然用
  `TURNOUT_TOKEN`。
- 部署后的健康检查要把 401 `setup_required` 识别成"等待初始化"而不是部署失败。

---

# 第 3 部分：公共事项

## 3.1 顺带修正的过时注释

- `internal/config/config.go:166-172`：仍写着"nft policy denies the diverted subnet"。
- `internal/api/ui.go:33-35`：仍写着"nft rules unconditionally deny the diverted client subnet"；
  另外"页面向操作者要 token"一段补上 HTTPS 的说明。
- `deploy/node/nft.conf.tmpl` 的注释补一句：内网全开依赖 API 的 HTTPS + 强制 token。

nft 规则本身不改。

## 3.2 实施顺序

1. **PR 1：HTTPS**（第 1 部分）。token 逻辑保持现状，单独可测：明文跳转、证书生成 / 续期 / SAN 重签、
   所有调用方改 https。
2. **PR 2：强制 token**（第 2 部分），依赖 PR 1。
3. 两个 PR **合并后一起部署**，不单独上线 PR 2（否则 setup code 会明文传输）。

## 3.3 迁移与上线

| 节点现状 | 升级后行为 |
|---|---|
| yaml 已有 `api.token` | 照常可用；UI 顶部提示"建议轮换为节点本地 token"，轮换后 yaml 里的值被清空 |
| `api.token` 为空 | 进入 `setup`，在操作者完成初始化前，除 `/healthz` 外的 API 全部 401。healthwatch 这段时间的记录会失败 |
| 所有节点 | 18080 改为 HTTPS；旧的 http 书签自动跳转；笔记本侧需更新到新版 Makefile / 脚本 |

上线顺序：

1. 先在 10.100.6.15 上 `make redeploy`，依次验证：明文跳转、浏览器指纹核对、初始化、轮换、reset、
   healthwatch 自动读 token 和 pin、`make status` 经 pin 访问、伪造到期时间触发续期后 pin 不变。
2. 再逐个节点 redeploy，每个节点部署完立刻在 UI 里完成初始化，缩短 401 窗口。
3. 每次 redeploy 前后照例核对 `subscriptions:` 块哈希不变。本改动不碰订阅，但 setup / rotate 会经
   `configstore` 重写 gateway.yaml（和现有 API 写回一样会丢注释），要确认订阅块原样保留。

## 3.4 测试

Go（`internal/api` 及新的 TLS 包）：

- TLS：首次启动生成 key + cert，权限 0600 / 0644；SAN 包含 127.0.0.1 和 ingress IP；续期后证书变、
  SPKI pin 不变；SAN 变化触发重签且热替换（同一个 listener 上新握手拿到新证书）；
  `enabled: false` + 非回环 listen 时 `config.Load` 报错；自有证书路径不触发生成。
- 明文：同一端口发明文 `GET /ui/` → 308 到 https；明文 `POST` → 400，handler 不被调用。
- token：无 token 时 `/api/status` → 401 `setup_required`，`/healthz`、`/api/auth/state` 可访问；
  setup code 错误 → 401；token 格式错误 → 400；成功 → 文件 0600、setup code 文件已删、新 token 立即
  生效；第二次 setup → 409；并发两个 setup 只有一个成功；rotate 后旧 token 立即 401；
  优先级文件 > yaml；reset 后两者都清空、重启进入 `setup`。
- healthwatch：pin 匹配时正常，pin 不匹配时拒绝连接。
- `ui_test.go` 现有的路由一致性断言覆盖新增的 `/api/auth/*` 路径。

前端：`make ui` 构建通过；在节点上手动走一遍初始化（含证书报错页面下复制按钮的回退）。

## 3.5 残留风险

- **首次访问的 TOFU**：浏览器的"继续前往"不强制核对指纹。操作者跳过核对时，首次连接仍可能被
  同网段的中间人劫持。缓解：初始化页首的核对提示、指纹走 SSH / 飞书带外分发；经常使用的运维可以把
  证书导入系统信任（`CA:false`，只对这个节点有效），之后不再弹警告。若嫌每年续期重新确认麻烦，
  后续可改为"每节点一个带 name constraints 的小 CA + 叶子证书"，不在本次范围。
- 自签证书每年续期一次，浏览器要重新确认、已导入信任的要重新导入；程序化调用方因为钉公钥不受影响。
- 节点被拿下时私钥一并泄露，需要 `--rotate-tls-key` 并更新所有 pin；这种情况下 token 也应同时轮换。
- 持有 token 即拥有全部权限，没有只读角色；轮换可以把其他人踢出去，恢复靠 SSH reset。
- 前端生成 token 的前提是操作者的浏览器可信；格式校验挡不住"故意设一个弱 token"，但操作者本来
  就有全部权限，这不构成新的攻击面。
- 登录页、`/healthz`、`/api/auth/state` 仍对内网可见，只暴露节点存在和初始化状态。
