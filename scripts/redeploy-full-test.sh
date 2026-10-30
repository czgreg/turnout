#!/usr/bin/env bash
# redeploy-full-test.sh — assert redeploy-full.sh leaves no copy of the
# node's gateway.yaml behind, on every way it can end.
#
# The pulled yaml holds every subscription URL with its credentials, and the
# repository lives in a synced folder. Before this was fixed, every redeploy
# left the yaml in /tmp, in build/turnout-stage/ and inside
# build/turnout-stage.tgz on this machine, and world-readable under /tmp on
# the node.
#
# Runs a COPY of the real script in a sandbox repo root, with stub ssh / scp
# and a fake stage.sh, so nothing touches a node or the real build/:
#
#   success         — deploy completes; local copies gone, unrelated stage
#                     files kept, node-side rm present in the remote command,
#                     remote command parses, the pull ran under umask 077.
#   install_fails   — install.sh exits non-zero on the node.
#   stage_fails     — stage.sh fails after copying the yaml into build/.
#   pull_fails      — ssh dies mid-pull, leaving a partial file.
#   interrupted     — SIGTERM to the process group while staging, as Ctrl-C
#                     sends SIGINT to it.
#
# Run: scripts/redeploy-full-test.sh
set -uo pipefail
cd "$(dirname "$0")/.."

HOST="redeploy-test.invalid"
MARKER="SECRET_MARKER_token=$(date +%s)$$"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  PASS  %s\n' "$*"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL  %s\n' "$*"; }

SANDBOX=$(mktemp -d)
cleanup_test() {
  rm -rf "$SANDBOX"
  rm -f /tmp/gw-"$HOST"-* /tmp/stage-"$HOST"-* /tmp/install-"$HOST"-*
}
trap cleanup_test EXIT

mkdir -p "$SANDBOX/scripts" "$SANDBOX/bin" "$SANDBOX/rec"
cp scripts/redeploy-full.sh "$SANDBOX/scripts/redeploy-full.sh"

# ── stubs ────────────────────────────────────────────────────────────────

# ssh: dispatch on the remote command (always the last argument).
cat > "$SANDBOX/bin/ssh" <<'EOF'
#!/usr/bin/env bash
cmd="${@: -1}"
REC="$SANDBOX_REC"
case "$cmd" in
  *"cat /etc/turnout/gateway.yaml"*)
    umask > "$REC/pull_umask"
    printf 'api:\n  listen: "0.0.0.0:18080"\nsubscriptions:\n  - name: s1\n    url: "https://example.invalid/sub?%s"\n' "$FAKE_MARKER"
    [ "${FAKE_PULL:-ok}" = "fail" ] && exit 255
    exit 0 ;;
  *"install.sh"*)
    printf '%s' "$cmd" > "$REC/install_cmd"
    # The remote command is: sudo -n bash -c '<inner>'. Parse <inner> with
    # bash -n so a quoting mistake fails here, not on a production node.
    inner="${cmd#sudo -n bash -c \'}"; inner="${inner%\'}"
    if bash -n -c "$inner" 2>"$REC/install_syntax"; then echo ok > "$REC/install_parse"; fi
    echo "INSTALL_EXIT=${FAKE_INSTALL_EXIT:-0}"
    exit 0 ;;
  *"read -r TOK"*)
    cat >/dev/null
    echo '{"turnout":{"gateway_version":"test","services":{"turnout-gateway":"active"}}}'
    exit 0 ;;
  *)
    printf '%s\n' "$cmd" >> "$REC/unexpected"
    exit 1 ;;
esac
EOF

cat > "$SANDBOX/bin/scp" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$SANDBOX_REC/scp"
exit 0
EOF

# The script sleeps while services restart; the drill has nothing to wait for.
cat > "$SANDBOX/bin/sleep" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF

# stage.sh: copy the yaml where the real one does, plus an unrelated file
# that must survive, then build the tarball (which embeds the yaml).
cat > "$SANDBOX/scripts/stage.sh" <<'EOF'
#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")/.."
mkdir -p build/turnout-stage
cp "$GATEWAY_YAML" build/turnout-stage/gateway.yaml
echo binary > build/turnout-stage/turnout-gateway
case "${FAKE_STAGE:-ok}" in
  fail) exit 1 ;;
  hang) touch build/.staging; exec /bin/sleep 30 ;;
esac
tar -czf build/turnout-stage.tgz -C build turnout-stage
EOF
chmod +x "$SANDBOX"/bin/* "$SANDBOX/scripts/"*.sh

export SANDBOX_REC="$SANDBOX/rec" FAKE_MARKER="$MARKER"
run() { # env... -> runs the script in the sandbox, sets RC and LOG
  rm -rf "$SANDBOX/rec"/* "$SANDBOX/build"
  LOG="$SANDBOX/run.log"
  env PATH="$SANDBOX/bin:$PATH" REMOTE_USER=tester "$@" \
    bash "$SANDBOX/scripts/redeploy-full.sh" "$HOST" > "$LOG" 2>&1
  RC=$?
}

# No file anywhere this script could have written still holds the marker.
assert_no_copies() { # case-name
  local leaks=""
  for f in /tmp/gw-"$HOST"-* "$SANDBOX/build/turnout-stage/gateway.yaml" "$SANDBOX/build/turnout-stage.tgz"; do
    [ -e "$f" ] && leaks="$leaks $f"
  done
  if grep -rlsa "$MARKER" "$SANDBOX/build" /tmp/gw-"$HOST"-* >/dev/null 2>&1; then
    leaks="$leaks (marker found)"
  fi
  if [ -z "$leaks" ]; then ok "$1: no local copy of the yaml left"
  else bad "$1: left behind:$leaks"; fi
}

echo "redeploy-full.sh cleanup drill"

# ── success ──────────────────────────────────────────────────────────────
run FAKE_INSTALL_EXIT=0
[ "$RC" -eq 0 ] && ok "success: exit 0" || { bad "success: exit $RC"; tail -5 "$LOG"; }
assert_no_copies success
[ -e "$SANDBOX/build/turnout-stage/turnout-gateway" ] \
  && ok "success: unrelated stage files kept" || bad "success: deleted more than the yaml"
grep -q 'rm -rf /tmp/turnout-stage /tmp/turnout-stage.tgz' "$SANDBOX/rec/install_cmd" 2>/dev/null \
  && ok "success: node-side copies removed in the remote command" || bad "success: no node-side rm in the remote command"
[ -s "$SANDBOX/rec/install_parse" ] \
  && ok "success: remote install command parses" || bad "success: remote command does not parse: $(cat "$SANDBOX/rec/install_syntax" 2>/dev/null)"
[ "$(cat "$SANDBOX/rec/pull_umask" 2>/dev/null)" = "0077" ] \
  && ok "success: pull ran under umask 077" || bad "success: pull umask = $(cat "$SANDBOX/rec/pull_umask" 2>/dev/null)"
[ ! -s "$SANDBOX/rec/unexpected" ] || bad "success: unexpected ssh call: $(cat "$SANDBOX/rec/unexpected")"

# ── install fails on the node ────────────────────────────────────────────
run FAKE_INSTALL_EXIT=1
[ "$RC" -ne 0 ] && ok "install_fails: exit $RC" || bad "install_fails: exit 0"
assert_no_copies install_fails

# ── stage.sh fails after copying the yaml ────────────────────────────────
run FAKE_STAGE=fail
[ "$RC" -ne 0 ] && ok "stage_fails: exit $RC" || bad "stage_fails: exit 0"
assert_no_copies stage_fails

# ── ssh dies mid-pull ────────────────────────────────────────────────────
run FAKE_PULL=fail
[ "$RC" -ne 0 ] && ok "pull_fails: exit $RC" || bad "pull_fails: exit 0"
assert_no_copies pull_fails

# ── interrupted while staging ────────────────────────────────────────────
# Job control gives the run its own process group; signalling the group is
# what a terminal does on Ctrl-C.
rm -rf "$SANDBOX/rec"/* "$SANDBOX/build"
set -m
env PATH="$SANDBOX/bin:$PATH" REMOTE_USER=tester FAKE_STAGE=hang \
  bash "$SANDBOX/scripts/redeploy-full.sh" "$HOST" > "$SANDBOX/run.log" 2>&1 &
pid=$!
set +m
for _ in $(seq 1 50); do [ -e "$SANDBOX/build/.staging" ] && break; /bin/sleep 0.1; done
if [ -e "$SANDBOX/build/turnout-stage/gateway.yaml" ]; then
  ok "interrupted: yaml was staged before the signal"
else
  bad "interrupted: stage never started"
fi
kill -TERM -- -"$pid" 2>/dev/null
wait "$pid"; RC=$?
[ "$RC" -ne 0 ] && ok "interrupted: exit $RC" || bad "interrupted: exit 0"
assert_no_copies interrupted

printf '\n  PASS %d   FAIL %d\n' "$PASS" "$FAIL"
exit "$FAIL"
