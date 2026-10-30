#!/usr/bin/env bash
# api-pin.sh — print the SPKI pin of a node's control-plane certificate.
#
#   scripts/api-pin.sh ops@<host>          # cached in .turnout/<host>.pin
#   scripts/api-pin.sh --refresh ops@<host>
#
# The control plane speaks HTTPS with a self-signed certificate the node
# mints itself (api.tls). Calls from the laptop (Makefile, deploy.sh) pin the
# certificate's public key with curl --pinnedpubkey, so they need the pin
# before the first request. It is read over SSH — the channel the operator
# already trusts to administer the node — never from the HTTPS port itself,
# which is the thing being verified.
#
# The pin survives certificate renewals (the node re-signs with the same
# key). It changes only after `turnout-gateway --rotate-tls-key`; then curl
# fails with exit 90 and you re-run this with --refresh.
#
# Output: the base64 pin on stdout, nothing else (Makefile captures it).
set -euo pipefail

refresh=0
if [ "${1:-}" = "--refresh" ]; then
  refresh=1
  shift
fi
node="${1:?usage: api-pin.sh [--refresh] user@host}"
host="${node#*@}"
cert="${API_TLS_CERT:-/var/lib/turnout/api-tls/cert.pem}"

cache_dir="$(cd "$(dirname "$0")/.." && pwd)/.turnout"
cache="$cache_dir/$host.pin"

if [ "$refresh" -eq 0 ] && [ -s "$cache" ]; then
  cat "$cache"
  exit 0
fi

pem=$(ssh -o ConnectTimeout=8 -o BatchMode=yes "$node" "cat '$cert'" 2>/dev/null) || {
  echo "api-pin: cannot read $cert on $node over ssh — has turnout-gateway started with api.tls enabled?" >&2
  exit 1
}
# SHA-256 over the DER SubjectPublicKeyInfo, base64 — curl's sha256// format.
# Works with both OpenSSL and the LibreSSL that ships with macOS.
pin=$(printf '%s\n' "$pem" \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | base64)
[ -n "$pin" ] || { echo "api-pin: could not derive a pin from $cert on $node" >&2; exit 1; }

mkdir -p "$cache_dir"
printf '%s\n' "$pin" > "$cache"
printf '%s\n' "$pin"
