#!/usr/bin/env bash
# scripts/stage.sh — produce a deployable tarball for a bypass-role node.
#
# Outputs $OUT_DIR/turnout-stage.tgz containing:
#   turnout-gateway          (linux/amd64, built from this checkout, version-stamped)
#   mihomo                (1.19.x linux/amd64, the data plane)
#   geoip.metadb          (mihomo's MaxMind DB; required by geoip routing rules)
#   gateway.yaml          (operator-supplied; defaults to ./gateway.yaml)
#   <deploy/node/* files> (install.sh, *.service, nft.conf.tmpl,
#                          iproute.sh, logrotate-turnout.conf)
#   rule-sets/*.mrs       (cn infra + tags referenced by gateway.yaml's
#                          whitelist, fetched from MetaCubeX /meta/ branch)
#
# Engine is always mihomo. No sing-box binary is shipped: the only thing that
# needed it was whitelistexpand's geoip decompile, and that whole chain went
# away with the upstream console integration. mihomo reads .mrs directly.
#
# Usage on operator workstation:
#   cp configs/gateway.example.yaml gateway.yaml   # then edit subscription URL + node values
#   scripts/stage.sh
#   scp build/turnout-stage.tgz ops@<node>:/tmp/
#   ssh ops@<node> 'cd /tmp && tar -xzf turnout-stage.tgz && sudo bash turnout-stage/install.sh'
#
# Env overrides:
#   GATEWAY_YAML       path to gateway.yaml (default: ./gateway.yaml)
#   MIHOMO_VERSION     mihomo version       (default: 1.19.26)
#   STAGE_CACHE        cache dir for downloaded binaries (default: ./.cache)
#   OUT_DIR            output directory (default: ./build)
#   GOARCH             target arch (default: amd64; set arm64 for ARM nodes)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GATEWAY_YAML="${GATEWAY_YAML:-./gateway.yaml}"
MIHOMO_VERSION="${MIHOMO_VERSION:-1.19.26}"
STAGE_CACHE="${STAGE_CACHE:-./.cache}"
OUT_DIR="${OUT_DIR:-./build}"
GOARCH="${GOARCH:-amd64}"

log() { printf '[stage] %s\n' "$*"; }
fail() { printf '[stage][FAIL] %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Without an explicit yaml the staged tarball would be useless. The
# preferred flow for an existing node is
# `make redeploy NODE=<user>@<host>` (or `scripts/redeploy-full.sh <host>`) —
# that pulls /etc/turnout/gateway.yaml from the node and feeds it to this
# script via GATEWAY_YAML, so the staged tarball never lies about what the
# node will end up running. Only fall back to ./gateway.yaml + plain
# `make stage` when bootstrapping a fresh node that has no on-disk config yet.
[ -f "$GATEWAY_YAML" ] || fail "gateway.yaml not found at $GATEWAY_YAML.
       For an existing node, prefer:  make redeploy NODE=<user>@<host>  /  scripts/redeploy-full.sh <host>
       For a fresh node, copy:        configs/gateway.example.yaml → ./gateway.yaml
                                       and fill in subscription URL + node values."

mkdir -p "$OUT_DIR" "$STAGE_CACHE"
STAGE_DIR="$OUT_DIR/turnout-stage"
rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# 1. Build turnout-gateway for the target platform.
# Version is `git describe --tags --always --dirty`: tag if present, short
# sha otherwise, with `-dirty` suffix when the worktree has uncommitted
# changes. Injected into main.Version so /api/proxies/active.turnout
# .gateway_version reports it — `dev` means the binary was built off-tree,
# which is exactly the case we want to flag during incident triage.
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
case "$VERSION" in
  *-dirty)
    log "WARNING: worktree dirty — version=$VERSION will lie about what's deployed."
    log "         commit your changes first if this is going to a node you care about."
    ;;
esac
log "building turnout-gateway (linux/$GOARCH, version=$VERSION)"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build \
  -ldflags="-s -w -X main.Version=$VERSION" \
  -o "$STAGE_DIR/turnout-gateway" ./cmd/gateway
ls -lh "$STAGE_DIR/turnout-gateway" | awk '{print "[stage] turnout-gateway", $5}'

# 1b. Health sampler. Ships with the gateway so every node records the same
# state (pool churn, reloads, DNS, direct-DNS reachability, resources) for
# later optimisation. No ldflags: it has no version variable.
log "building turnout-healthwatch (linux/$GOARCH)"
GOOS=linux GOARCH="$GOARCH" CGO_ENABLED=0 go build \
  -o "$STAGE_DIR/turnout-healthwatch" ./cmd/healthwatch
ls -lh "$STAGE_DIR/turnout-healthwatch" | awk '{print "[stage] turnout-healthwatch", $5}'

# 2. mihomo data-plane binary. Use the "compatible" build (non-AMD64-v3)
# so it runs on older forwarding-node hardware classes that lack AVX2.
M_PKG="mihomo-linux-${GOARCH}-compatible-v${MIHOMO_VERSION}"
M_GZ="$STAGE_CACHE/${M_PKG}.gz"
if [ ! -f "$M_GZ" ]; then
  url="https://github.com/MetaCubeX/mihomo/releases/download/v${MIHOMO_VERSION}/${M_PKG}.gz"
  log "downloading $url"
  curl -fsSL "$url" -o "$M_GZ" || fail "could not download mihomo"
fi
gunzip -c "$M_GZ" > "$STAGE_DIR/mihomo"
chmod 0755 "$STAGE_DIR/mihomo"
ls -lh "$STAGE_DIR/mihomo" | awk '{print "[stage] mihomo", $5}'

# geoip.metadb — mihomo's geoip-cn routing rule requires this MaxMind DB;
# without it mihomo refuses to load geoip rule-sets.
METADB_FILE="$STAGE_CACHE/geoip.metadb"
if [ ! -s "$METADB_FILE" ]; then
  url="https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"
  log "downloading $url"
  curl -fsSL "$url" -o "$METADB_FILE" || fail "could not download geoip.metadb"
fi
cp "$METADB_FILE" "$STAGE_DIR/geoip.metadb"
ls -lh "$STAGE_DIR/geoip.metadb" | awk '{print "[stage] geoip.metadb", $5}'

# 3. Operator gateway.yaml.
# ⛔ subscriptions[] in this yaml is operator-owned and per-node-specific.
# If this stage came from `redeploy-full.sh` (yaml pulled from a node),
# the subscriptions block is going right back to that node — DO NOT edit
# entries between pull and push. See CLAUDE.md.
cp "$GATEWAY_YAML" "$STAGE_DIR/gateway.yaml"
log "gateway.yaml copied from $GATEWAY_YAML"

# 5. deploy/node/* — install.sh, *.service, nft.conf.tmpl, iproute.sh,
# logrotate-turnout.conf. The sing-box data-plane unit was retired in the
# 2026-06 upstream engine cleanup; only mihomo + gateway + nft units ship.
cp deploy/node/install.sh \
   deploy/node/iproute.sh \
   deploy/node/render-rules.sh \
   deploy/node/nft.conf.tmpl \
   deploy/node/logrotate-turnout.conf \
   deploy/node/turnout-mihomo.service \
   deploy/node/turnout-gateway.service \
   deploy/node/turnout-nft.service \
   deploy/node/turnout-healthwatch.service \
   "$STAGE_DIR/"
chmod 0755 "$STAGE_DIR/install.sh" "$STAGE_DIR/iproute.sh" "$STAGE_DIR/render-rules.sh"
log "deploy/node/* files staged"

# 6. Rule-set .mrs blobs. Pre-fetched into the tarball so mihomo can load
# geosite-cn / geoip-cn (route infra) and any tags already selected in
# gateway.yaml.whitelist.{geosites,geoips} as type=file at startup.
# Tags NOT referenced by gateway.yaml are fetched on-demand by the runtime
# API (PUT /api/whitelist) when an operator selects them.
#
# Per-URL cache in $STAGE_CACHE/rule-sets/. Delete that dir to force
# re-fetch.
RULESETS_CACHE="$STAGE_CACHE/rule-sets"
mkdir -p "$RULESETS_CACHE" "$STAGE_DIR/rule-sets"

# Always pre-fetch the two infra rule-sets used by the route classifier.
# MetaCubeX URL paths use stem-only filenames; we save to <tag>.mrs locally
# to match the renderer's rule_set path lookup.
RULESET_ENTRIES=(
  "geosite-cn.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.mrs"
  "geoip-cn.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs"
  # Ad blocking. Shipped unconditionally, even when route.ad_block is off:
  # the switch is flipped from the console at runtime and a toggle cannot
  # download anything. A missing file does NOT stop mihomo (verified: it
  # logs "initial rule provider ... no such file" and keeps serving), so
  # the rule would silently match nothing — see the hard check below.
  #
  # Three sets, all of them referenced by internal/mihomo.AdRuleSets:
  #   category-ads-all  MetaCubeX .mrs, the ad-exchange core (903)
  #   anti-ad           CN-oriented plain-text list (~112k)
  #   cname-ads         AdGuard disguised-CNAME domains, plain text (~11.7k)
  # The last two are text so no conversion step is needed.
  "category-ads-all.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.mrs"
  "anti-ad.txt|https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-domains.txt"
  "cname-ads.txt|https://raw.githubusercontent.com/AdguardTeam/cname-trackers/master/data/combined_disguised_ads_justdomains.txt"
)

# Tags requested by gateway.yaml as full URLs — legacy form, kept for yaml
# that still has explicit url: fields under data_plane.route.geosite_url etc.
# Strip any extension and rewrite under /meta/ + .mrs.
while IFS= read -r u; do
  case "$u" in
    *"/geo/geosite/"*)
      stem=$(basename "$u" .srs); stem=${stem%.mrs}
      RULESET_ENTRIES+=("geosite-${stem}.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/${stem}.mrs")
      ;;
    *"/geo/geoip/"*)
      stem=$(basename "$u" .srs); stem=${stem%.mrs}
      RULESET_ENTRIES+=("geoip-${stem}.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/${stem}.mrs")
      ;;
    *) RULESET_ENTRIES+=("$(basename "$u")|$u") ;;
  esac
done < <(grep -oE 'https://[^"[:space:]]+\.(srs|mrs)' "$GATEWAY_YAML" | sort -u)

# Tags from gateway.yaml's whitelist (geosites: [tag, ...] and geoips:
# [tag, ...] — bare strings, no urls).
#
# The renderer looks each whitelist tag up as `<tags_dir>/<tag>.mrs`
# (internal/mihomo/groups.go buildRuleProviders) — the tag IS the filename.
# So `- openai` under geosites must land as rule-sets/openai.mrs, NOT
# geosite-openai.mrs. Two separate passes are needed because the upstream
# directory depends on WHICH list the tag came from (geosite vs geoip), and
# the prefix only disambiguates the legacy `geosite-openai` spelling.
#
# The mode resets on any key line (`something:`), not just column-0 ones:
# `domain_suffix:` and `geosites:` are both indented inside `whitelist:`,
# and resetting only at column 0 let domain names leak into this list.
read_wl_list() {
  # $1 = key name (geosites|geoips)
  awk -v key="$1:" '
    /^[[:space:]]*[a-zA-Z_-]+:/ { mode = ($1 == key) ? "in" : ""; next }
    mode=="in" && /^[[:space:]]*-[[:space:]]/ {
      sub(/^[[:space:]]*-[[:space:]]*/, "")
      sub(/[[:space:]]*#.*/, "")
      gsub(/^[[:space:]]+|[[:space:]]+$/, "")
      gsub(/"/, "")
      if ($0 != "") print $0
    }
  ' "$GATEWAY_YAML"
}

WL_GEOSITES=()
while IFS= read -r tag; do
  [ -n "$tag" ] && WL_GEOSITES+=("$tag")
done < <(read_wl_list geosites)

WL_GEOIPS=()
while IFS= read -r tag; do
  [ -n "$tag" ] && WL_GEOIPS+=("$tag")
done < <(read_wl_list geoips)

RULE_META="https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo"

for tag in "${WL_GEOSITES[@]:-}"; do
  [ -n "$tag" ] || continue
  case "$tag" in
    geosite-*) stem="${tag#geosite-}"; save="${tag}.mrs" ;;
    geoip-*)   stem="${tag#geoip-}";   save="${tag}.mrs" ;;
    *)         stem="$tag";            save="${tag}.mrs" ;;
  esac
  RULESET_ENTRIES+=("${save}|${RULE_META}/geosite/${stem}.mrs")
done

for tag in "${WL_GEOIPS[@]:-}"; do
  [ -n "$tag" ] || continue
  case "$tag" in
    geoip-*)   stem="${tag#geoip-}";   save="${tag}.mrs" ;;
    geosite-*) stem="${tag#geosite-}"; save="${tag}.mrs" ;;
    *)         stem="$tag";            save="${tag}.mrs" ;;
  esac
  RULESET_ENTRIES+=("${save}|${RULE_META}/geoip/${stem}.mrs")
done

# Tags from gateway.yaml pools[].rule_sets — pools need their .mrs files
# just as much as whitelist entries. If stage.sh skips them, mihomo fails
# on startup with "file not found" for the rule-provider.
POOL_TAGS=()
while IFS= read -r tag; do
  POOL_TAGS+=("$tag")
done < <(awk '
  /^pools:/                     { inpools=1; next }
  inpools && /^[^[:space:]]/    { inpools=0 }
  inpools && /rule_sets:/        { inrs=1; next }
  inpools && /^[[:space:]]*[a-zA-Z_-]+:/ && !/rule_sets:/ { inrs=0 }
  inrs && /^[[:space:]]*-[[:space:]]/ {
    sub(/^[[:space:]]*-[[:space:]]*/, "")
    sub(/[[:space:]]*#.*/, "")
    gsub(/"|'"'"'/, "")
    if ($0 ~ /^(geosite|geoip)-/) print $0
  }
' "$GATEWAY_YAML")

for tag in "${POOL_TAGS[@]:-}"; do
  case "$tag" in
    geosite-*) stem="${tag#geosite-}"
               RULESET_ENTRIES+=("${tag}.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/${stem}.mrs") ;;
    geoip-*)   stem="${tag#geoip-}"
               RULESET_ENTRIES+=("${tag}.mrs|https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/${stem}.mrs") ;;
  esac
done

# Tags + URLs from gateway.yaml pools[].rule_lists — external classical lists
# (one full rule per line, e.g. DOMAIN-SUFFIX,x / DOMAIN-KEYWORD,y). Stored
# verbatim as <tag>.list: the renderer declares them behavior=classical
# format=text, so no .mrs conversion is possible or wanted (mrs only covers
# domain/ipcidr and would drop the keyword lines).
#
# Expected shape (block style, keys tag then url):
#   rule_lists:
#     - tag: gemini
#       url: "https://yfamilys.com/rule/Gemini.list"
RULE_LIST_TAGS=()
while IFS=$'\t' read -r rl_tag rl_url; do
  [ -n "$rl_tag" ] && [ -n "$rl_url" ] || continue
  RULE_LIST_TAGS+=("$rl_tag")
  RULESET_ENTRIES+=("${rl_tag}.list|${rl_url}")
done < <(awk '
  function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
  function flush() {
    if (tag != "" && url != "") print tag "\t" url
    tag = ""; url = ""
  }
  /^[[:space:]]*rule_lists:[[:space:]]*$/ { inrl = 1; flush(); next }
  inrl && /^[[:space:]]*-[[:space:]]*tag:/ {
    flush()
    t = $0; sub(/^.*tag:[[:space:]]*/, "", t); gsub(/["'"'"']/, "", t)
    tag = trim(t); next
  }
  inrl && /^[[:space:]]*url:/ {
    u = $0; sub(/^[[:space:]]*url:[[:space:]]*/, "", u); gsub(/["'"'"']/, "", u)
    url = trim(u); next
  }
  inrl && /^[[:space:]]*[a-zA-Z_-]+:/ { flush(); inrl = 0 }
  END { flush() }
' "$GATEWAY_YAML")

# Dedupe by save_name|url tuple (bash 3.2 has no associative arrays).
DEDUPED_ENTRIES=()
SEEN=$'\n'
for e in "${RULESET_ENTRIES[@]:-}"; do
  case "$SEEN" in
    *$'\n'"$e"$'\n'*) ;;
    *)
      DEDUPED_ENTRIES+=("$e")
      SEEN="$SEEN$e"$'\n'
      ;;
  esac
done

log "fetching ${#DEDUPED_ENTRIES[@]} rule-set files (cn infra + ads + gateway.yaml whitelist)"
fetched=0
skipped=0
for entry in "${DEDUPED_ENTRIES[@]:-}"; do
  fname="${entry%%|*}"
  url="${entry#*|}"
  cached="$RULESETS_CACHE/$fname"
  if [ ! -s "$cached" ]; then
    if ! curl -fsSL --retry 2 --max-time 30 "$url" -o "$cached.tmp"; then
      log "  skip $fname (fetch failed: $url)"
      rm -f "$cached.tmp"
      skipped=$((skipped+1))
      continue
    fi
    mv "$cached.tmp" "$cached"
  fi
  cp "$cached" "$STAGE_DIR/rule-sets/$fname"
  fetched=$((fetched+1))
done
log "rule-sets staged: $fetched ok, $skipped skipped ($(du -sh "$STAGE_DIR/rule-sets" | cut -f1))"

# Normalize the two plain-text ad lists. Both ship with '#' headers; the
# AdGuard list also carries a few "*.domain" wildcards. mihomo's text provider
# would treat those lines as literal strings, so they would silently never
# match — the same class of failure as a missing .mrs, which is why it is done
# here rather than trusted to the upstream format.
# Portable form: BSD sed has no -i without an argument, so write and rename.
for f in anti-ad.txt cname-ads.txt; do
  src="$STAGE_DIR/rule-sets/$f"
  [ -s "$src" ] || continue
  grep -v '^#' "$src" | grep -v '^[[:space:]]*$' | sed 's/^\*\.//' > "$src.tmp"
  mv "$src.tmp" "$src"
done

# Ad blocking is the one rule-set group whose absence is silent at runtime, so
# it gets a hard gate instead of the tolerate-and-continue treatment above.
# internal/mihomo.AdRuleSets is the source of truth; keep this list in step.
for f in category-ads-all.mrs anti-ad.txt cname-ads.txt; do
  [ -s "$STAGE_DIR/rule-sets/$f" ] \
    || fail "$f missing — ad blocking would silently match nothing; check network or the STAGE_CACHE/rule-sets copy"
done

# Pool rule_lists get the same hard gate. A missing file makes mihomo log
# "no such file" and keep serving, so the domains would quietly fall through
# to the default class — the exact routing the operator asked to override.
for tag in "${RULE_LIST_TAGS[@]:-}"; do
  [ -n "$tag" ] || continue
  [ -s "$STAGE_DIR/rule-sets/$tag.list" ] \
    || fail "$tag.list missing — pool rule_lists would silently route through the default class; check network or the STAGE_CACHE/rule-sets copy"
done

# 7. Tarball.
TARBALL="$OUT_DIR/turnout-stage.tgz"
tar -czf "$TARBALL" -C "$OUT_DIR" turnout-stage
log "wrote $TARBALL ($(du -h "$TARBALL" | cut -f1))"

cat <<EOF
[stage] DONE.

Next steps:
  scp $TARBALL ops@<node>:/tmp/
  ssh ops@<node>
  $ cd /tmp && tar -xzf turnout-stage.tgz
  $ sudo bash turnout-stage/install.sh
EOF
