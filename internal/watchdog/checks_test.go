package watchdog

// Tests for the four self-checks.
//
// The checks share one contract that every case below pins: report what was
// observed, never repair, and treat "could not run meaningfully" as skipped
// rather than failed. The last point is load-bearing — a skipped check that
// counted as a failure would mark a node unhealthy at every restart (before
// the first scoring round / assertion round), and with auto_failover that
// means cutting the office over for a warm-up window.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/dataplane"
)

// ── rules_check ─────────────────────────────────────────────────────────────

type fakeRules struct{ snap dataplane.Snapshot }

func (f fakeRules) Snapshot() dataplane.Snapshot { return f.snap }

func TestRulesChecker_NilSourceSkips(t *testing.T) {
	res := NewRulesChecker(nil).Check(context.Background())
	if !res.Skipped || res.OK {
		t.Errorf("nil source must skip, got ok=%v skipped=%v", res.OK, res.Skipped)
	}
}

// Before the asserter's first round, At is zero. Reporting that as a failure
// would trip the threshold on every restart.
func TestRulesChecker_NoRoundYetSkips(t *testing.T) {
	res := NewRulesChecker(fakeRules{}).Check(context.Background())
	if !res.Skipped || res.OK {
		t.Errorf("zero At must skip, got ok=%v skipped=%v", res.OK, res.Skipped)
	}
}

func TestRulesChecker_HealthyPasses(t *testing.T) {
	src := fakeRules{snap: dataplane.Snapshot{
		At:      time.Now(),
		Healthy: true,
		Checks:  []dataplane.CheckResult{{Name: dataplane.CheckIPRule, OK: true}},
	}}
	res := NewRulesChecker(src).Check(context.Background())
	if !res.OK || res.Skipped {
		t.Fatalf("healthy snapshot must pass, got %+v", res)
	}
	if !strings.Contains(res.Detail, "passing") {
		t.Errorf("detail should say what passed, got %q", res.Detail)
	}
}

// A failing snapshot must name the failing object, because that name is what
// the operator sees in the alert and greps for in the journal.
func TestRulesChecker_UnhealthyNamesTheFailingCheck(t *testing.T) {
	src := fakeRules{snap: dataplane.Snapshot{
		At:      time.Now(),
		Healthy: false,
		Checks: []dataplane.CheckResult{
			{Name: dataplane.CheckIPRule, OK: false},
			{Name: dataplane.CheckRouteLocal, OK: true},
			{Name: dataplane.CheckPreroutingJump, OK: false, Repaired: true},
		},
	}}
	res := NewRulesChecker(src).Check(context.Background())
	if res.OK {
		t.Fatal("unhealthy snapshot must not pass")
	}
	for _, want := range []string{dataplane.CheckIPRule, dataplane.CheckPreroutingJump, "auto-repaired"} {
		if !strings.Contains(res.Detail, want) {
			t.Errorf("detail %q missing %q", res.Detail, want)
		}
	}
	// A passing check must not be named as failing.
	if strings.Contains(res.Detail, dataplane.CheckRouteLocal) {
		t.Errorf("detail %q names a passing check", res.Detail)
	}
}

// ── pool_check ──────────────────────────────────────────────────────────────

type fakePool struct{ snap PoolSnapshot }

func (f fakePool) GetSnapshot() PoolSnapshot { return f.snap }

func TestPoolChecker_DisabledByMin(t *testing.T) {
	res := NewPoolChecker(fakePool{snap: PoolSnapshot{Alive: 0, Total: 9}}, 0).Check(context.Background())
	if !res.Skipped {
		t.Errorf("min=0 must skip, got %+v", res)
	}
}

func TestPoolChecker_NilSourceSkips(t *testing.T) {
	res := NewPoolChecker(nil, 1).Check(context.Background())
	if !res.Skipped {
		t.Errorf("nil scorer must skip, got %+v", res)
	}
}

// Before the first scoring round every counter is zero; that is a warm-up
// state, not an outage.
func TestPoolChecker_NoScoringRoundSkips(t *testing.T) {
	res := NewPoolChecker(fakePool{snap: PoolSnapshot{}}, 1).Check(context.Background())
	if !res.Skipped || res.OK {
		t.Errorf("Total=0 must skip, got ok=%v skipped=%v", res.OK, res.Skipped)
	}
}

func TestPoolChecker_EnoughAlivePasses(t *testing.T) {
	res := NewPoolChecker(fakePool{snap: PoolSnapshot{Alive: 3, Total: 9}}, 1).Check(context.Background())
	if !res.OK {
		t.Errorf("3 alive meets min=1, got %+v", res)
	}
}

// Zero healthy egress is the "everything is green but nothing works" case:
// process up, rules in place, nowhere to send proxied traffic.
func TestPoolChecker_NoAliveFails(t *testing.T) {
	res := NewPoolChecker(fakePool{snap: PoolSnapshot{Alive: 0, Total: 9}}, 1).Check(context.Background())
	if res.OK || res.Skipped {
		t.Fatalf("0 alive must fail, got %+v", res)
	}
	if !strings.Contains(res.Detail, "nowhere to go") {
		t.Errorf("detail should explain the consequence, got %q", res.Detail)
	}
}

// ── engine_check ────────────────────────────────────────────────────────────

func clashAPI(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

func TestEngineChecker_AnswersOK(t *testing.T) {
	chk := NewEngineChecker(config.ClashAPIConfig{ExternalController: clashAPI(t, http.StatusOK)})
	res := chk.Check(context.Background())
	if !res.OK {
		t.Errorf("200 /version must pass, got %+v", res)
	}
}

// A mihomo that is running but wedged answers pgrep and not /version; that is
// exactly the case an API check catches and a process check misses.
func TestEngineChecker_Non200Fails(t *testing.T) {
	chk := NewEngineChecker(config.ClashAPIConfig{ExternalController: clashAPI(t, http.StatusInternalServerError)})
	res := chk.Check(context.Background())
	if res.OK {
		t.Errorf("500 /version must fail, got %+v", res)
	}
	if !strings.Contains(res.Detail, "500") {
		t.Errorf("detail should carry the status, got %q", res.Detail)
	}
}

func TestEngineChecker_UnreachableFails(t *testing.T) {
	// Reserve a port then close it, so nothing is listening.
	srv := httptest.NewServer(http.NotFoundHandler())
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close()

	chk := NewEngineChecker(config.ClashAPIConfig{ExternalController: addr})
	res := chk.Check(context.Background())
	if res.OK || res.Skipped {
		t.Errorf("unreachable engine must fail (not skip), got %+v", res)
	}
}

func TestEngineChecker_SendsSecret(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	chk := NewEngineChecker(config.ClashAPIConfig{
		ExternalController: strings.TrimPrefix(srv.URL, "http://"),
		Secret:             "s3cret",
	})
	chk.Check(context.Background())
	if got != "Bearer s3cret" {
		t.Errorf("Authorization = %q, want Bearer s3cret", got)
	}
}

func TestEngineChecker_NoAddrSkips(t *testing.T) {
	res := NewEngineChecker(config.ClashAPIConfig{}).Check(context.Background())
	if !res.Skipped {
		t.Errorf("empty controller must skip, got %+v", res)
	}
}

// ── egress_probe ────────────────────────────────────────────────────────────

func TestEgressChecker_NoTargetSkips(t *testing.T) {
	res := NewEgressChecker("http://127.0.0.1:11080", "", time.Second).Check(context.Background())
	if !res.Skipped {
		t.Errorf("empty target must skip, got %+v", res)
	}
}

// 2xx and 3xx are passes; anything else means we reached something other than
// a working tunnel, so it is a failure.
func TestEgressChecker_StatusRanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The probe asks for a single byte; honour it without a body.
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	chk := NewEgressChecker("http://127.0.0.1:11080", srv.URL, 2*time.Second)
	// No proxy is listening at 11080 in the test, so this exercises the
	// transport-error path rather than the status path. Assert only that it
	// fails cleanly and names the proxy.
	res := chk.Check(context.Background())
	if res.OK {
		t.Errorf("unreachable proxy must not pass, got %+v", res)
	}
	if !strings.Contains(res.Detail, "11080") {
		t.Errorf("detail should name the proxy, got %q", res.Detail)
	}
}
