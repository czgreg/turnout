#!/usr/bin/env bash
# render-rules.sh — render /etc/turnout/nft.conf from the template + env.
#
# Extracted from install.sh's install_nft() so the control plane can re-render
# the ruleset after an operator edits client_subnet through the API
# (PUT /api/node/network). Two callers, one implementation: a second copy in
# Go would drift from this one on the next template change.
#
# Usage:
#   render-rules.sh            # render /etc/turnout/nft.conf in place
#   render-rules.sh --check    # verify inputs parse, write nothing
#
# Inputs (sourced from /etc/turnout/env, written by `turnout-gateway
# --print-env`): TURNOUT_CLIENT_SUBNET, TURNOUT_INGRESS_IFACE,
# TURNOUT_API_PORT, TURNOUT_API_ALLOW_FROM.
#
# The template ships next to this script (install.sh installs both into
# /etc/turnout/).

set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="/etc/turnout/env"
TMPL="$SELF_DIR/nft.conf.tmpl"
OUT="/etc/turnout/nft.conf"

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

die() { echo "render-rules: $*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || die "$ENV_FILE missing (re-run install.sh)"
[ -f "$TMPL" ]     || die "$TMPL missing (re-run install.sh)"

# shellcheck disable=SC1090
source "$ENV_FILE"

[ -n "${TURNOUT_CLIENT_SUBNET:-}" ] || die "TURNOUT_CLIENT_SUBNET missing in $ENV_FILE"
[ -n "${TURNOUT_API_PORT:-}" ]      || die "TURNOUT_API_PORT missing in $ENV_FILE"
[ -n "${TURNOUT_INGRESS_IFACE:-}" ] || die "TURNOUT_INGRESS_IFACE missing in $ENV_FILE"

# Render one `ip saddr <cidr> ... accept` line per api.allow_from entry.
# The template ends with a default accept for other sources, so these
# entries are additive and normally redundant.
# Refuse the exact diverted client subnet: this list gates the nft input
# chain only, and an entry inside client_subnet would suggest a protection
# that does not exist (the TPROXY chain decides what is proxied, and local
# destinations RETURN before any of it).
api_allow_rules=""
for cidr in ${TURNOUT_API_ALLOW_FROM:-}; do
  if [ "$cidr" = "$TURNOUT_CLIENT_SUBNET" ]; then
    die "api.allow_from must not contain the client_subnet ($cidr)"
  fi
  api_allow_rules="${api_allow_rules}    ip saddr $cidr tcp dport $TURNOUT_API_PORT accept"$'\n'
done
# Strip the trailing newline so the template's own line break is not doubled.
api_allow_rules="${api_allow_rules%$'\n'}"

if [ "$CHECK" = "1" ]; then
  echo "render-rules: OK (client_subnet=$TURNOUT_CLIENT_SUBNET ingress=$TURNOUT_INGRESS_IFACE api_port=$TURNOUT_API_PORT allow_from='${TURNOUT_API_ALLOW_FROM:-<none>}')"
  exit 0
fi

stage="$(mktemp "$OUT.stage.XXXXXX")"
trap 'rm -f "$stage" "$stage.2"' EXIT

sed -e "s|@CLIENT_SUBNET@|$TURNOUT_CLIENT_SUBNET|g" \
    -e "s|@INGRESS_IFACE@|$TURNOUT_INGRESS_IFACE|g" \
    -e "s|@API_PORT@|$TURNOUT_API_PORT|g" \
    "$TMPL" > "$stage"
# Substitute the multi-line allowlist separately: sed's `s` can't carry
# embedded newlines portably, so use awk to splice at the placeholder.
awk -v repl="$api_allow_rules" '
  $0 ~ /@API_ALLOW_RULES@/ { if (repl != "") print repl; next }
  { print }
' "$stage" > "$stage.2"

# Refuse to install a file nft cannot parse. `nft -c` is a syntax check that
# does not touch the live ruleset, so a bad template never reaches a node.
nft -c -f "$stage.2" >/dev/null 2>"$stage.2.err" \
  || die "rendered nft.conf fails 'nft -c': $(cat "$stage.2.err")"

install -m 0644 "$stage.2" "$OUT"
echo "render-rules: wrote $OUT (client_subnet=$TURNOUT_CLIENT_SUBNET ingress=$TURNOUT_INGRESS_IFACE api_port=$TURNOUT_API_PORT allow_from='${TURNOUT_API_ALLOW_FROM:-<none>}')"
