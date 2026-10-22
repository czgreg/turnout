# Makefile — turnout-gateway dev / deploy targets.
#
# Quick reference:
#   make help              # list targets
#   make setup-ssh NODE=ops@<host>   # 一次性：推公钥 + NOPASSWD sudo（先跑这个！）
#   make test              # go vet + go test
#   make ui                # 构建 Web 控制台（web/ → internal/api/ui/）
#   make deploy NODE=ops@<host>      # binary-only deploy (~10s)
#   make deploy-yaml NODE=ops@<host> # 仅推 gateway.yaml（不换二进制）
#   make redeploy NODE=ops@<host>    # ★ 全量重装（先拉节点 yaml + stage + install）
#   make status NODE=ops@<host>      # /api/status
#   make health NODE=ops@<host>      # /api/proxies/active
#   make nodes  NODE=ops@<host>      # /api/nodes/health
#   make logs   NODE=ops@<host>      # tail turnout-gateway 日志
#   make ssh    NODE=ops@<host>      # ssh 进节点
#
# NODE has NO default, on purpose. This repository serves whatever node the
# operator names, and a baked-in default is how you push to production while
# believing you are targeting a lab box. Every target that talks to a host
# depends on check-node and refuses to run without it.

NODE        ?=
NODE_HOST   := $(word 2,$(subst @, ,$(NODE)))
TURNOUT_API    ?= http://$(NODE_HOST):18080
# Bearer token for the control-plane API (api.token in gateway.yaml).
# Empty → no Authorization header, which is correct only when the node
# also leaves api.token empty. Export TURNOUT_TOKEN in your shell or pass
# `make TURNOUT_TOKEN=... status`.
TURNOUT_TOKEN  ?=
TURNOUT_AUTH   := $(if $(TURNOUT_TOKEN),-H "Authorization: Bearer $(TURNOUT_TOKEN)",)
GATEWAY_YAML?= ./gateway.yaml
GOOS        ?= linux
GOARCH      ?= amd64
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD)
LDFLAGS     := -s -w -X main.Version=$(VERSION)

SSH_OPTS    := -o StrictHostKeyChecking=no -o ConnectTimeout=8 -o BatchMode=yes
SSH         := ssh $(SSH_OPTS) $(NODE)
SCP         := scp $(SSH_OPTS)

.DEFAULT_GOAL := help

.PHONY: help
help:  ## 列出所有 target
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Guard for every host-touching target. Fails loudly rather than silently
# running ssh with an empty destination (which would either hang or hit the
# local machine).
.PHONY: check-node
check-node:
	@test -n "$(NODE)" || { \
	  echo "✗ NODE is required — it has no default on purpose."; \
	  echo "  Usage: make $(or $(MAKECMDGOALS),<target>) NODE=ops@<host>"; \
	  exit 1; }

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------

.PHONY: build
build:  ## 本地构建 (macOS dev)
	go build -o build/turnout-gateway ./cmd/gateway

.PHONY: build-linux
build-linux:  ## 交叉编译 linux/amd64（部署用）
	@mkdir -p build
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build \
	  -ldflags='$(LDFLAGS)' \
	  -o build/turnout-gateway-linux-amd64 ./cmd/gateway
	@echo "  built build/turnout-gateway-linux-amd64  version=$(VERSION)"

.PHONY: ui
ui:  ## 构建 Web 控制台：web/ → internal/api/ui/（需 Node 20.19+；产物要一起提交）
	cd web && npm ci && npm run build

.PHONY: ui-mock
ui-mock:  ## 本地起控制台 + mock 数据，不需要节点  http://localhost:5173/
	cd web && npm ci && npm run mock

.PHONY: test
test:  ## go vet + go test ./...
	go vet ./...
	go test ./...

.PHONY: stage
stage:  ## 打全量部署 tarball (build/turnout-stage.tgz)
	./scripts/stage.sh

# ---------------------------------------------------------------------------
# Deploy
# ---------------------------------------------------------------------------

.PHONY: deploy
deploy: check-node build-linux  ## ⚡ 热替换二进制 + 重启 (~10s)  NODE=ops@<host>
	scripts/deploy.sh --skip-build $(NODE_HOST)

.PHONY: deploy-yaml
deploy-yaml: check-node  ## 仅推 gateway.yaml + 重启  NODE=ops@<host> GATEWAY_YAML=./path/to/yaml
	@test -f $(GATEWAY_YAML) || (echo "GATEWAY_YAML not found: $(GATEWAY_YAML)" && exit 1)
	$(SCP) $(GATEWAY_YAML) $(NODE):/tmp/gateway.yaml.new
	$(SSH) 'sudo install -m0640 /tmp/gateway.yaml.new /etc/turnout/gateway.yaml && \
	  sudo systemctl restart turnout-gateway && rm -f /tmp/gateway.yaml.new && \
	  sleep 1 && sudo journalctl -u turnout-gateway -n 5 --no-pager'

.PHONY: redeploy
redeploy: check-node  ## ★ 安全全量重装：先拉节点 yaml，再 stage+install+verify  NODE=ops@<host>
	./scripts/redeploy-full.sh $(NODE_HOST)

.PHONY: deploy-full-LOCAL-YAML
deploy-full-LOCAL-YAML: check-node stage  ## ⚠️ 全量重装，使用本地 ./gateway.yaml（容易踩雷；优先用 redeploy）
	$(SCP) build/turnout-stage.tgz $(NODE):/tmp/
	$(SSH) 'cd /tmp && rm -rf turnout-stage && tar --no-same-owner -xzf turnout-stage.tgz && \
	  sudo bash turnout-stage/install.sh'

# ---------------------------------------------------------------------------
# Observe
# ---------------------------------------------------------------------------

.PHONY: status
status: check-node  ## GET /api/status
	@curl -s --max-time 5 $(TURNOUT_AUTH) $(TURNOUT_API)/api/status | python3 -m json.tool

.PHONY: health
health: check-node  ## GET /api/proxies/active
	@curl -s --max-time 5 $(TURNOUT_AUTH) $(TURNOUT_API)/api/proxies/active | python3 -m json.tool

.PHONY: observe
# observe.sh runs on the node; its knobs must be exported INSIDE the remote
# sudo shell — a plain `VAR=x make observe` never crosses ssh. Wrapped in
# `sudo bash -c` (not `sudo env`) because the deploy sudoers dropin allows
# /bin/bash but not /usr/bin/env.
SAMPLE_SECONDS ?= 6
EXPECT_SRC     ?=
OBSERVE_REMOTE  = sudo -n bash -c "export SAMPLE_SECONDS=$(SAMPLE_SECONDS) EXPECT_SRC=$(EXPECT_SRC); exec bash -s"

.PHONY: observe
observe: check-node  ## 分级观测流量路径（引流/拦截/DNS/判定/出口/回程）  NODE=ops@<host> [EXPECT_SRC=<终端IP>] [SAMPLE_SECONDS=6]
	$(SSH) '$(OBSERVE_REMOTE)' < scripts/observe.sh

.PHONY: observe-loop
observe-loop: check-node  ## 每 10 秒跑一次 observe，只看结论行（导流测试时开一个窗口盯着）  NODE=ops@<host>
	@while true; do \
	  out=$$($(SSH) '$(OBSERVE_REMOTE)' < scripts/observe.sh 2>/dev/null); \
	  printf '\n=== %s ===\n' "$$(date +%H:%M:%S)"; \
	  printf '%s\n' "$$out" | grep -E '窗口|细分|PASS|FAIL|IDLE|活跃连接|type|来源|期望源|pool eligible|默认路由' | sed 's/\x1b\[[0-9;]*m//g'; \
	  sleep 10; \
	done

.PHONY: verify
verify: check-node  ## 旁挂验收：入向/回程/TPROXY/自检/分流/池/产物（需 sudo）  NODE=ops@<host>
	$(SSH) 'sudo bash -s' < scripts/verify-bypass.sh

.PHONY: watchdog
watchdog: check-node  ## GET /api/watchdog/status（旁挂健康；不健康时 HTTP 503 但仍带 body）
	@curl -s --max-time 5 $(TURNOUT_AUTH) $(TURNOUT_API)/api/watchdog/status | python3 -m json.tool

.PHONY: nodes
nodes: check-node  ## GET /api/nodes/health (probe + passive stats)
	@curl -s --max-time 5 $(TURNOUT_AUTH) $(TURNOUT_API)/api/nodes/health | python3 -m json.tool

.PHONY: logs
logs: check-node  ## tail turnout-gateway 日志
	$(SSH) 'sudo journalctl -fu turnout-gateway --no-pager'

.PHONY: mihomo-logs
mihomo-logs: check-node  ## tail turnout-mihomo 日志
	$(SSH) 'sudo journalctl -fu turnout-mihomo --no-pager'

.PHONY: ssh
ssh: check-node  ## 直接 ssh 进节点  NODE=ops@<host>
	@ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 $(NODE)

.PHONY: nft
nft: check-node  ## 查看 turnout nft table
	$(SSH) 'sudo nft list table inet turnout'

# ---------------------------------------------------------------------------
# One-time bootstrap (run once per node before anything else)
# ---------------------------------------------------------------------------

.PHONY: setup-ssh
setup-ssh: check-node  ## ★ 一次性推公钥 + NOPASSWD sudo（先跑！）  NODE=ops@<host>
	./scripts/setup-ssh.sh $(NODE)

.PHONY: clean
clean:  ## 清理 build 产物
	rm -rf build/
