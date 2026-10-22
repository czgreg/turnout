package dataplane

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// fakeRunner records every command and replays canned output keyed by a
// prefix of the joined argv. Anything unmatched returns empty output with
// no error, so a test only has to describe the calls it cares about.
type fakeRunner struct {
	mu    sync.Mutex
	calls []string
	out   map[string]string
	errs  map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{out: map[string]string{}, errs: map[string]error{}}
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) (string, error) {
	joined := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, joined)
	f.mu.Unlock()
	for k, v := range f.out {
		if strings.HasPrefix(joined, k) {
			return v, f.errs[k]
		}
	}
	return "", f.errs[joined]
}

func (f *fakeRunner) called(substr string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func testAsserter(t *testing.T, fr *fakeRunner) *Asserter {
	t.Helper()
	a := NewAsserter("10.1.0.0/16", "ens19", 7893, true)
	if a == nil {
		t.Fatal("NewAsserter returned nil for a valid TPROXY config")
	}
	a.runner = fr.run
	return a
}

// The rule-present output taken verbatim from node 92.
const liveRuleOutput = `0:	from all lookup local
101:	from all fwmark 0x44 lookup 101
32766:	from all lookup main
32767:	from all lookup default
`

// The exact state during the 2026-08-12 outage: table 101 survived, the
// rule did not.
const outageRuleOutput = `0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default
`

// liveChainOutput is what iproute.sh leaves in TURNOUT_TPROXY. The jump
// alone is not enough — these four rules are what actually intercept.
const liveChainOutput = `-N TURNOUT_TPROXY
-A TURNOUT_TPROXY -m addrtype --dst-type LOCAL -j RETURN
-A TURNOUT_TPROXY -p tcp -m tcp --dport 53 -j RETURN
-A TURNOUT_TPROXY -p tcp -j TPROXY --on-port 7893 --on-ip 127.0.0.1 --tproxy-mark 0x44/0x44
-A TURNOUT_TPROXY -p udp -m udp ! --dport 53 -j TPROXY --on-port 7893 --on-ip 127.0.0.1 --tproxy-mark 0x44/0x44
`

func TestCheckIPRule_PresentDoesNotRepair(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip rule show"] = liveRuleOutput
	a := testAsserter(t, fr)

	res := a.checkIPRule(context.Background())
	if !res.OK {
		t.Fatalf("expected OK with rule present, got %+v", res)
	}
	if res.Repaired {
		t.Error("must not repair a healthy rule")
	}
	if fr.called("ip rule add") {
		t.Error("must not call `ip rule add` when the rule is already present")
	}
}

func TestCheckIPRule_MissingIsDetectedAndRepaired(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip rule show"] = outageRuleOutput
	a := testAsserter(t, fr)

	res := a.checkIPRule(context.Background())
	if res.OK {
		t.Fatal("expected NOT OK when the fwmark rule is missing — this is the 2026-08-12 outage")
	}
	if !res.Repaired {
		t.Errorf("expected repair to succeed, got %+v", res)
	}
	if !fr.called("ip rule add fwmark 0x44 lookup 101 pref 101") {
		t.Errorf("repair must add the rule with pref 101 to match iproute.sh; calls=%v", fr.calls)
	}
}

// Some kernels print the mark without the 0x prefix. Accepting only one
// spelling would make the asserter "repair" a rule that is already there,
// adding a duplicate every 30s.
func TestCheckIPRule_AcceptsBareHexSpelling(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip rule show"] = "101:\tfrom all fwmark 44 lookup 101\n"
	a := testAsserter(t, fr)

	res := a.checkIPRule(context.Background())
	if !res.OK {
		t.Errorf("`fwmark 44` must count as present, got %+v", res)
	}
	if fr.called("ip rule add") {
		t.Error("must not add a duplicate rule")
	}
}

// A rule for a different table must not satisfy the check.
func TestCheckIPRule_WrongTableIsNotAMatch(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip rule show"] = "101:\tfrom all fwmark 0x44 lookup 100\n"
	a := testAsserter(t, fr)

	if res := a.checkIPRule(context.Background()); res.OK {
		t.Error("fwmark 0x44 pointing at table 100 (the sing-box-era table) must not pass")
	}
}

func TestCheckRouteLocal_MissingIsRepaired(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip route show table 101"] = ""
	a := testAsserter(t, fr)

	res := a.checkRouteLocal(context.Background())
	if res.OK {
		t.Fatal("empty table 101 must not pass")
	}
	if !fr.called("ip route add local 0.0.0.0/0 dev lo table 101") {
		t.Errorf("expected the local-default repair; calls=%v", fr.calls)
	}
}

func TestCheckRouteLocal_PresentPasses(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip route show table 101"] = "local default dev lo scope host\n"
	a := testAsserter(t, fr)

	res := a.checkRouteLocal(context.Background())
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
	if fr.called("ip route add") {
		t.Error("must not re-add an existing route")
	}
}

func TestCheckPreroutingJump_PresentPasses(t *testing.T) {
	fr := newFakeRunner()
	fr.out["iptables -t mangle -S PREROUTING"] =
		"-P PREROUTING ACCEPT\n-A PREROUTING -s 10.1.0.0/16 -i ens19 -j TURNOUT_TPROXY\n"
	a := testAsserter(t, fr)

	res := a.checkPreroutingJump(context.Background())
	if !res.OK {
		t.Errorf("expected OK, got %+v", res)
	}
	if fr.called("-A PREROUTING") {
		t.Error("must not re-attach an existing jump")
	}
}

// The jump must be matched by its parts, not by argument order: iptables-save
// prints -s before -i, while iproute.sh adds -i before -s.
func TestCheckPreroutingJump_MatchesRegardlessOfArgOrder(t *testing.T) {
	for _, line := range []string{
		"-A PREROUTING -s 10.1.0.0/16 -i ens19 -j TURNOUT_TPROXY",
		"-A PREROUTING -i ens19 -s 10.1.0.0/16 -j TURNOUT_TPROXY",
	} {
		fr := newFakeRunner()
		fr.out["iptables -t mangle -S PREROUTING"] = line + "\n"
		a := testAsserter(t, fr)
		if res := a.checkPreroutingJump(context.Background()); !res.OK {
			t.Errorf("should match %q, got %+v", line, res)
		}
	}
}

func TestCheckPreroutingJump_WrongSubnetIsNotAMatch(t *testing.T) {
	fr := newFakeRunner()
	fr.out["iptables -t mangle -S PREROUTING"] =
		"-A PREROUTING -s 10.2.0.0/16 -i ens19 -j TURNOUT_TPROXY\n"
	a := testAsserter(t, fr)

	if res := a.checkPreroutingJump(context.Background()); res.OK {
		t.Error("a jump for a different client subnet must not satisfy the check")
	}
}

// All data-path objects present must read as healthy regardless of whether
// any client traffic is flowing — an idle segment is not a fault, and
// /healthz must not 503 all night.
func TestOnce_AllObjectsPresentIsHealthy(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip rule show"] = liveRuleOutput
	fr.out["ip route show table 101"] = "local default dev lo scope host\n"
	fr.out["iptables -t mangle -S PREROUTING"] =
		"-A PREROUTING -i ens19 -s 10.1.0.0/16 -j TURNOUT_TPROXY\n"
	fr.out["iptables -t mangle -S TURNOUT_TPROXY"] = liveChainOutput
	a := NewAsserter("10.1.0.0/16", "ens19", 7893, true)
	a.runner = fr.run

	a.once(context.Background())
	snap := a.Snapshot()
	if !snap.Healthy {
		t.Errorf("all data-path objects present must be healthy; checks=%+v", snap.Checks)
	}
	if snap.At.IsZero() {
		t.Error("snapshot timestamp must be set after a round")
	}
}

// A persistent failure must alert once, then stay quiet, then alert again
// on recovery. 120 identical Lark messages an hour is how alerting gets
// muted, and a muted alert is the same as no alert.
func TestOnce_AlertsOnTransitionOnly(t *testing.T) {
	fr := newFakeRunner()
	fr.out["ip rule show"] = outageRuleOutput // broken
	fr.out["ip route show table 101"] = "local default dev lo scope host\n"
	fr.out["iptables -t mangle -S PREROUTING"] =
		"-A PREROUTING -i ens19 -s 10.1.0.0/16 -j TURNOUT_TPROXY\n"
	fr.out["iptables -t mangle -S TURNOUT_TPROXY"] = liveChainOutput
	a := NewAsserter("10.1.0.0/16", "ens19", 7893, true)
	a.runner = fr.run

	var mu sync.Mutex
	var subjects []string
	a.Emit = func(subject, _ string, _ bool) {
		mu.Lock()
		subjects = append(subjects, subject)
		mu.Unlock()
	}

	a.once(context.Background())
	a.once(context.Background())
	a.once(context.Background())
	mu.Lock()
	nFail := len(subjects)
	mu.Unlock()
	if nFail != 1 {
		t.Fatalf("expected exactly 1 alert across 3 failing rounds, got %d: %v", nFail, subjects)
	}

	// Now heal the underlying state; the next round must emit recovery.
	fr.mu.Lock()
	fr.out["ip rule show"] = liveRuleOutput
	fr.mu.Unlock()
	a.once(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(subjects) != 2 {
		t.Fatalf("expected a recovery alert, got %v", subjects)
	}
	if !strings.Contains(subjects[1], "recovered") {
		t.Errorf("second alert should be the recovery, got %q", subjects[1])
	}
}

// A config with no TPROXY path must yield no asserter, so /healthz falls
// back to liveness-only instead of repairing objects toward port 0.
func TestNewAsserter_DisabledWithoutDataPath(t *testing.T) {
	if a := NewAsserter("", "ens19", 7893, true); a != nil {
		t.Error("empty client_subnet must disable the asserter")
	}
	if a := NewAsserter("10.1.0.0/16", "ens19", 0, true); a != nil {
		t.Error("tproxy_port 0 must disable the asserter")
	}
}

// An empty chain is the failure the jump check structurally cannot see:
// traffic reaches TURNOUT_TPROXY, matches nothing, and falls through to the
// default route — back to the firewall. Verified on a live node 2026-10-22
// by flushing the chain: every other check, and the watchdog, stayed green.
func TestCheckChainRules_EmptyChainFailsAndRepairs(t *testing.T) {
	fr := newFakeRunner()
	fr.out["iptables -t mangle -S TURNOUT_TPROXY"] = "-N TURNOUT_TPROXY\n"
	a := testAsserter(t, fr)

	res := a.checkChainRules(context.Background())
	if res.OK {
		t.Fatal("an empty TPROXY chain must not be healthy")
	}
	if !res.Repaired {
		t.Fatalf("expected repair, got %+v", res)
	}
	for _, want := range []string{"-I TURNOUT_TPROXY 1", "-A TURNOUT_TPROXY -p tcp", "-A TURNOUT_TPROXY -p udp"} {
		if !fr.called(want) {
			t.Errorf("repair should run %q; calls=%v", want, fr.calls)
		}
	}
}

// A partially damaged chain (TCP rule gone, UDP intact) repairs only the
// missing object and leaves the rest alone.
func TestCheckChainRules_PartialDamageRepairsOnlyWhatIsMissing(t *testing.T) {
	fr := newFakeRunner()
	fr.out["iptables -t mangle -S TURNOUT_TPROXY"] = `-N TURNOUT_TPROXY
-A TURNOUT_TPROXY -m addrtype --dst-type LOCAL -j RETURN
-A TURNOUT_TPROXY -p udp -j TPROXY --on-port 7893 --on-ip 127.0.0.1 --tproxy-mark 0x44/0x44
`
	a := testAsserter(t, fr)
	res := a.checkChainRules(context.Background())
	if res.OK || !res.Repaired {
		t.Fatalf("expected a repaired failure, got %+v", res)
	}
	if fr.called("-I TURNOUT_TPROXY 1") {
		t.Error("the local RETURN was present and must not be re-inserted")
	}
	if fr.called("-A TURNOUT_TPROXY -p udp") {
		t.Error("the UDP rule was present and must not be re-added")
	}
	if !fr.called("-A TURNOUT_TPROXY -p tcp") {
		t.Error("the missing TCP rule must be re-added")
	}
}

func TestCheckChainRules_IntactChainIsHealthy(t *testing.T) {
	fr := newFakeRunner()
	fr.out["iptables -t mangle -S TURNOUT_TPROXY"] = liveChainOutput
	a := testAsserter(t, fr)
	if res := a.checkChainRules(context.Background()); !res.OK {
		t.Fatalf("intact chain must be healthy, got %+v", res)
	}
}
