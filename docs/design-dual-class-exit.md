# Dual-class exit: AI → US, everything else → Asia

Status: implemented 2026-10-23.

## Why

The gateway originally had one egress pool (`default-pool`) filtered by a single
global `data_plane.url_test.node_pattern`. With a US-only pattern every
whitelisted destination paid a 200–300 ms RTT, so a cold YouTube open took
~3 s even when the node was healthy, and an occasional 10 %-loss window
pushed individual requests to 3–15 s.

The operator's Shadowrocket config separates AI/Google traffic from general
browsing. This change brings the same idea to the gateway, with two classes:

| Class | Destinations | Egress | Per-terminal |
|---|---|---|---|
| AI (`ai-pool`) | OpenAI, Anthropic/Claude, Gemini, Antigravity, `geosite-category-ai-!cn`, Perplexity | US only | yes — stable US IP |
| Other (default) | Google Search/Gmail, YouTube, GitHub, social, streaming, everything else whitelisted | Asia: JP/SG/HK, US as fallback | yes — stable Asia IP |

Each terminal therefore has two stable egress IPs: one US for AI, one Asia
for everything else. AI services never see the Asia IP and general traffic
never sees the US IP.

Gemini is deliberately part of the AI class (US) because the operator chose
"keep Gemini with AI, only US". YouTube is part of the default class. A user
signed into a Google account will therefore present the Asia IP to
Search/Gmail/YouTube and the US IP to Gemini; this is the intended split.

## Model

Two kinds of named pools coexist:

- **Legacy pool** — only `requires_passing` / `rule_sets`. Members are a
  probe-gated subset of `default-pool`; with `load_balance.per_terminal: true`
  its rule sets route through the unified `perterm` sub-rule (one terminal,
  one IP across all classes). Behavior is unchanged.
- **Class pool** — any of `node_pattern`, `size`, `per_terminal`,
  `domain_suffix` is present. It has its own candidate set, its own
  top-N membership, and its own routing:
  - `per_terminal: true` → `fb-<pool>-<ip>` fallback groups plus a
    `perterm-<pool>` sub-rule.
  - `per_terminal: false` → one shared load-balance group.
  - `domain_suffix` rules are emitted before `rule_sets` and before the
    global whitelist, so an exact domain can override a broader geosite hit
    (Gemini inside `geosite-google`).

Class routing is opt-in per pool. Existing configs with no class fields keep
the old unified-perterm semantics, and `TestRenderer_PerTerminalNamedPoolUnified`
still pins that behavior.

## Config

```yaml
data_plane:
  url_test:
    # Default/other class: Asia, US as fallback. Go RE2 — no lookahead.
    node_pattern: "日本|🇯🇵|\\bJP|新加坡|🇸🇬|\\bSG|香港|🇭🇰|\\bHK|美国|🇺🇸|\\bUS"

pools:
  - name: ai-pool
    node_pattern: "美国|🇺🇸|\\bUS"
    size: 4
    per_terminal: true
    rule_sets:
      - geosite-openai
      - geosite-anthropic
      - geosite-category-ai-!cn
      - geosite-perplexity
    domain_suffix:
      - claude.ai
      - gemini.google.com
      - generativelanguage.googleapis.com
      - aistudio.google.com
      - alkalimakersuite-pa.clients6.google.com
      - deepmind.google
      - deepmind.com
      - cloudcode-pa.googleapis.com
      - proxy.antigravity.google.com
      - antigravity.google.com
```

`subscriptions:` is untouched (see CLAUDE.md).

## Implementation

- `internal/config/config.go` — `PoolConfig` gains `NodePattern`, `Size`,
  `PerTerminal *bool`, `DomainSuffix`; `IsClassPool()` / `PerTerminalEnabled()`;
  `validatePools()` rejects invalid regexes, duplicate names, negative sizes,
  and `per_terminal` without `client_subnet`.
- `internal/nodescorer/scorer.go` — candidate discovery is the union of the
  global pattern and every pool pattern; `computePoolMembers` selects class
  members from all qualified nodes by pattern, ranks by long EWMA, caps at
  `Size`, and keeps incumbents unless a challenger beats the worst by
  `SwapThresholdScore`. The global `node_pattern` is also a **hard routing
  filter** for the default pool: a non-matching node stays scored and
  url-tested (class pools and recovery need it) but cannot enter the default
  top-K. Without this, changing the default region is blocked by the old
  region's incumbents in `state` (observed 2026-10-23: the pattern moved to
  Asia but the K-gating kept selecting the US momo nodes).
- `internal/mihomo/groups.go` — `poolDispatchMembers()` resolves a pool's
  members (scorer list → pattern → default-pool) and class pools emit their own
  per-terminal fallback groups. An empty pool renders a `select [DIRECT]`
  stub so mihomo never sees an empty group.
- `internal/mihomo/rules.go` — class pools dispatch to `perterm-<pool>` or
  their shared group; exact domains are emitted first.
- `internal/mihomo/perterminal.go` — generalized `perTerminalSlicesFor` /
  `perTerminalFallbackGroupsFor`; `PoolAssignmentForIP` and
  `PoolPerTerminalGroupName` for the API.
- `internal/api/terminal.go` — `/api/pool/terminal` reports a `pools` array
  with each per-terminal class's primary/secondary/active node.
- `internal/api/proxies.go` — `/api/proxies/active` now lists named class
  pools (they are not members of `out`).

## Risks / notes

- One terminal, two IPs (AI class vs default class). This is the intended
  trade-off; the anti-bot rule "one identity, one IP" now holds per class.
- AI/Gemini runs at US RTT (~200 ms). Changing the `ai-pool` pattern to
  `日本|🇯🇵|\bJP` moves Gemini to Japan without touching any other class.
- The first scoring rounds after widening the global pattern have to
  accumulate EWMA for the new Asia nodes; expect 1–2 rounds (5–10 min) of
  transitions, throttled by `hot_reload_min_interval`.
- `--validate` and `install.sh --render-once` render with no outbounds, so
  they only check the bootstrap/syntax path. The real multi-node render is
  covered by unit tests; after deploy, confirm the first hot reload via
  `/api/proxies/active` and a real request.

## Verification

```bash
go vet ./...
go test ./...
make build-linux
```

After deploy:

- `GET /api/nodes/health` — JP/SG/HK nodes appear and become qualified.
- `GET /api/proxies/active` — `default-pool` routing members are mostly Asia;
  `ai-pool` members are US.
- `GET /api/pool/terminal?ip=<terminal>` — the default class and `ai-pool`
  each show primary/secondary.
- `curl -w 'tls=%{time_appconnect} ttfb=%{time_starttransfer}'` to YouTube
  should drop to ~0.08–0.10 s / ~0.2–0.3 s on a JP node; AI endpoints keep
  the US timing.
