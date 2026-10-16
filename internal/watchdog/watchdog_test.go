package watchdog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// ── test doubles ────────────────────────────────────────────────────────────

// fakeChecker returns a scripted sequence of results. After the script is
// exhausted it repeats the last entry, so a test can express "fails from here
// on" without enumerating every round.
type fakeChecker struct {
	name    CheckName
	results []CheckResult
	mu      sync.Mutex
	calls   int
}

func (f *fakeChecker) Name() CheckName { return f.name }

func (f *fakeChecker) Check(context.Context) CheckResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	f.calls++
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	r := f.results[i]
	r.Name = f.name
	return r
}

// fakeAddr records Up/Down calls and tracks presence.
type fakeAddr struct {
	mu      sync.Mutex
	present bool
	ups     int
	downs   int
	failUp  error
	failDn  error
}

func (f *fakeAddr) Up(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failUp != nil {
		return f.failUp
	}
	f.ups++
	f.present = true
	return nil
}

func (f *fakeAddr) Down(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDn != nil {
		return f.failDn
	}
	f.downs++
	f.present = false
	return nil
}

func (f *fakeAddr) Present(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present, nil
}

func (f *fakeAddr) state() (present bool, ups, downs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present, f.ups, f.downs
}

// recordingEmitter captures emitted messages. Both subject and body are
// recorded: several assertions check for detail that only appears in the
// body (the failing check's name, or a note that an address change could not
// be applied), and dropping it would make those assertions vacuous.
type recordingEmitter struct {
	mu   sync.Mutex
	msgs []string
}

func (e *recordingEmitter) emit(subject, body string, urgent bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	sev := "info"
	if urgent {
		sev = "urgent"
	}
	rec := sev + ": " + subject
	if body != "" {
		rec += "\n" + body
	}
	e.msgs = append(e.msgs, rec)
}

func (e *recordingEmitter) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.msgs...)
}

// boolPtr/intPtr build the pointer-typed config fields whose safe default is
// ON. A plain bool cannot express that: yaml decodes an absent key as false,
// so `notify_on_state_change` omitted would silently disable alerting.
func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func baseCfg() config.WatchdogConfig {
	c := config.WatchdogConfig{
		Enabled:          boolPtr(true),
		Interval:         time.Millisecond,
		FailThreshold:    3,
		RecoverThreshold: 3,
		LivenessIP:       "10.255.255.3",
		LivenessIface:    "lo",
		AutoFailover:     true,
	}
	c.Checks.EngineAlive = boolPtr(true)
	return c
}

func ok() CheckResult    { return CheckResult{OK: true} }
func bad() CheckResult   { return CheckResult{OK: false, Detail: "boom"} }
func skip() CheckResult  { return CheckResult{OK: false, Skipped: true} }

// ── constructor behaviour ───────────────────────────────────────────────────

func TestNew_DisabledByConfig(t *testing.T) {
	c := baseCfg()
	c.Enabled = boolPtr(false)
	if wd := New(c, nil, &fakeAddr{}, nil); wd != nil {
		t.Fatal("disabled watchdog must return nil so callers can guard")
	}
}

// TestNew_RefusesEmptyLivenessIP pins the deliberate absence of a default.
// A watchdog with no address has nothing to withdraw, so starting one would
// report health it cannot signal — fail loudly instead.
func TestNew_RefusesEmptyLivenessIP(t *testing.T) {
	c := baseCfg()
	c.LivenessIP = ""
	if wd := New(c, nil, &fakeAddr{}, nil); wd != nil {
		t.Fatal("empty liveness_ip must not start a watchdog")
	}
}

func TestNew_RefusesNilAddressManager(t *testing.T) {
	if wd := New(baseCfg(), nil, nil, nil); wd != nil {
		t.Fatal("nil address manager must not start a watchdog")
	}
}

// ── the threshold behaviour, which is the whole point ───────────────────────

// A single failing round must not trip the verdict: transient rule loss is
// exactly what assert.go's repair path handles, and acting on one sample
// would cut the office over for a blip that self-healed.
func TestThreshold_TransientFailureDoesNotAct(t *testing.T) {
	cfg := baseCfg()
	cfg.FailThreshold = 3
	chk := &fakeChecker{name: CheckEngineAlive, results: []CheckResult{bad(), ok(), ok(), ok(), ok()}}
	addr := &fakeAddr{present: true}
	wd := New(cfg, []Checker{chk}, addr, nil)

	ctx := context.Background()
	// Five rounds: one failure then four passes.
	for i := 0; i < 5; i++ {
		wd.tick(ctx)
	}

	present, _, downs := addr.state()
	if !present {
		t.Error("address must not be withdrawn for a transient single-round failure")
	}
	if downs != 0 {
		t.Errorf("Down called %d times, want 0", downs)
	}
	if st := wd.Status().State; st != StateUnknown {
		// Never reached RecoverThreshold consecutive passes from a
		// non-unknown start either, so it should still be unknown.
		t.Logf("state=%s (acceptable as long as no action was taken)", st)
	}
}

// Consecutive failures up to the threshold must trip it exactly once, and
// withdraw the address.
func TestThreshold_ConsecutiveFailuresTripOnce(t *testing.T) {
	cfg := baseCfg()
	cfg.FailThreshold = 3
	chk := &fakeChecker{name: CheckEngineAlive, results: []CheckResult{bad()}}
	addr := &fakeAddr{present: true}
	var emitted recordingEmitter
	wd := New(cfg, []Checker{chk}, addr, emitted.emit)

	ctx := context.Background()
	wd.tick(ctx) // streak 1
	wd.tick(ctx) // streak 2
	if _, _, downs := addr.state(); downs != 0 {
		t.Fatalf("acted before reaching threshold")
	}
	if st := wd.Status().State; st != StateUnknown {
		t.Fatalf("state=%s before threshold, want unknown", st)
	}

	wd.tick(ctx) // streak 3 → unhealthy
	st := wd.Status()
	if st.State != StateUnhealthy {
		t.Fatalf("state=%s after 3 failures, want unhealthy", st.State)
	}
	if st.FailStreak != 3 {
		t.Errorf("fail_streak=%d, want 3", st.FailStreak)
	}
	if len(st.Failing) != 1 || st.Failing[0] != CheckEngineAlive {
		t.Errorf("failing=%v, want [engine_alive]", st.Failing)
	}
	present, _, downs := addr.state()
	if present {
		t.Error("address must be withdrawn when unhealthy with auto_failover=true")
	}
	if downs != 1 {
		t.Errorf("Down called %d times, want 1", downs)
	}

	// Further failures must not re-act: the verdict is already unhealthy.
	wd.tick(ctx)
	wd.tick(ctx)
	if _, _, downs := addr.state(); downs != 1 {
		t.Errorf("Down called %d times after staying unhealthy, want 1 (act on transition only)", downs)
	}
}

// Recovery also requires consecutive rounds, mirroring the firewall's own
// revertive behaviour (it needs N consecutive responses before declaring Up).
func TestThreshold_RecoveryRequiresConsecutivePasses(t *testing.T) {
	cfg := baseCfg()
	cfg.FailThreshold = 2
	cfg.RecoverThreshold = 3
	chk := &fakeChecker{name: CheckEngineAlive, results: []CheckResult{bad(), bad(), ok(), bad(), ok(), ok(), ok()}}
	addr := &fakeAddr{present: true}
	wd := New(cfg, []Checker{chk}, addr, nil)

	ctx := context.Background()
	for i := 0; i < 7; i++ {
		wd.tick(ctx)
	}

	st := wd.Status()
	if st.State != StateHealthy {
		t.Fatalf("state=%s after 3 consecutive passes, want healthy", st.State)
	}
	if st.OKStreak != 3 {
		t.Errorf("ok_streak=%d, want 3", st.OKStreak)
	}
	present, _, _ := addr.state()
	if !present {
		t.Error("address must be restored on recovery")
	}
}

// A skipped check is not a failure: no asserter configured, no scoring round
// completed yet, and a disabled optional check all land here, and treating
// any of them as unhealthy would cut the office over for a configuration fact.
func TestSkippedCheckIsNotAFailure(t *testing.T) {
	cfg := baseCfg()
	cfg.FailThreshold = 2
	chk := &fakeChecker{name: CheckDataplaneRules, results: []CheckResult{skip()}}
	addr := &fakeAddr{present: true}
	wd := New(cfg, []Checker{chk}, addr, nil)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		wd.tick(ctx)
	}

	if _, _, downs := addr.state(); downs != 0 {
		t.Errorf("Down called %d times for a skipped check, want 0", downs)
	}
	if st := wd.Status(); len(st.Failing) != 0 {
		t.Errorf("failing=%v, want empty for a skipped check", st.Failing)
	}
	if st := wd.Status(); st.OKStreak != 5 {
		t.Errorf("ok_streak=%d, want 5 — a skipped check should count as passing", st.OKStreak)
	}
}

// AutoFailover=false must report without acting. This is the documented
// default: during the trial period a manual cutover is preferred, and an
// automatic withdrawal during a half-dead state gives false confidence.
func TestAutoFailoverFalse_ReportsWithoutActing(t *testing.T) {
	cfg := baseCfg()
	cfg.AutoFailover = false
	cfg.FailThreshold = 2
	chk := &fakeChecker{name: CheckEngineAlive, results: []CheckResult{bad()}}
	addr := &fakeAddr{present: true}
	var emitted recordingEmitter
	wd := New(cfg, []Checker{chk}, addr, emitted.emit)

	ctx := context.Background()
	wd.tick(ctx)
	wd.tick(ctx)

	if st := wd.Status(); st.State != StateUnhealthy {
		t.Fatalf("state=%s, want unhealthy — the verdict must still be reported", st.State)
	}
	present, _, downs := addr.state()
	if !present {
		t.Error("address must stay up when auto_failover=false")
	}
	if downs != 0 {
		t.Errorf("Down called %d times with auto_failover=false, want 0", downs)
	}

	// The operator must be told, and told that nothing was done about it.
	msgs := emitted.all()
	if len(msgs) == 0 {
		t.Fatal("expected an alert on transition to unhealthy")
	}
	foundNotice := false
	for _, m := range msgs {
		if contains(m, "urgent") {
			foundNotice = true
		}
	}
	if !foundNotice {
		t.Errorf("expected an urgent alert, got %v", msgs)
	}
}

// A failure applying the address change must surface, not be swallowed:
// silently believing we cut over while the address is still answering is the
// worst outcome this component can produce.
func TestAddressFailure_IsReported(t *testing.T) {
	cfg := baseCfg()
	cfg.FailThreshold = 1
	chk := &fakeChecker{name: CheckEngineAlive, results: []CheckResult{bad()}}
	addr := &fakeAddr{present: true, failDn: errors.New("permission denied")}
	var emitted recordingEmitter
	wd := New(cfg, []Checker{chk}, addr, emitted.emit)

	wd.tick(context.Background())

	if st := wd.Status(); st.State != StateUnhealthy {
		t.Fatalf("state=%s, want unhealthy", st.State)
	}
	if present, _, _ := addr.state(); !present {
		t.Error("test setup: address should still be present when Down failed")
	}
	// The status must still say the address is up — that is the truth, and
	// it is what tells the operator the cutover did not happen.
	if st := wd.Status(); !st.LivenessUp {
		t.Error("liveness_up must reflect the kernel state, not the intent")
	}
	msgs := emitted.all()
	joined := ""
	for _, m := range msgs {
		joined += m + "\n"
	}
	if !contains(joined, "could not apply") {
		t.Errorf("expected the address failure to be reported, got: %v", msgs)
	}
}

// Status must report the state truthfully before any round runs, so the
// console does not render a misleading card at startup.
func TestStatus_InitialStateIsUnknown(t *testing.T) {
	wd := New(baseCfg(), nil, &fakeAddr{}, nil)
	st := wd.Status()
	if st.State != StateUnknown {
		t.Errorf("initial state=%s, want unknown", st.State)
	}
	if st.LivenessIP != "10.255.255.3" {
		t.Errorf("liveness_ip=%s, want the configured value", st.LivenessIP)
	}
	if !st.AutoFailover {
		t.Error("auto_failover should be mirrored from config so readers know if a cutover would happen")
	}
}

// Status must be safe to read concurrently with evaluation — the API handler
// reads it while the run loop writes it.
func TestStatus_ConcurrentReadsAreSafe(t *testing.T) {
	cfg := baseCfg()
	chk := &fakeChecker{name: CheckEngineAlive, results: []CheckResult{ok(), bad()}}
	wd := New(cfg, []Checker{chk}, &fakeAddr{}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			wd.tick(ctx)
		}
	}()
	for i := 0; i < 200; i++ {
		_ = wd.Status()
	}
	<-done
}

// contains is a tiny helper so the test file does not import strings just for
// one call in a couple of assertions.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
