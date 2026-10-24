// Package watchdog is the bypass role's health reporter.
//
// # Why this exists
//
// A bypass gateway is invisible to the traffic it serves: the firewall's PBR
// rule diverts traffic to us, and the only signal the firewall has about our
// state is an IP-Link probe. On Huawei USG6000E that probe is limited to
// `mode icmp` or `mode arp` — the platform has no HTTP/TCP probe that can be
// bound to policy routing (智能选路的 health check supports them, but it
// belongs to a different routing model and cannot drive a PBR rule).
//
// An ICMP probe proves the kernel is alive. It says nothing about whether the
// data path works. The failure modes that actually hurt are exactly the ones
// ICMP cannot see:
//
//   - mihomo crashed or is crash-looping → every proxied flow dies
//   - the TPROXY rules were flushed → diverted traffic is forwarded out
//     instead of delivered to mihomo (this is the 2026-08-12 outage shape,
//     see internal/dataplane/assert.go)
//   - every egress node is down → the classifier has nowhere to send
//     whitelisted traffic
//
// In all three the host answers pings within microseconds, so the firewall
// keeps diverting the entire office into a black hole while reporting the
// next-hop as healthy.
//
// The fix is to make the accuracy of that signal this host's responsibility:
// while the data path passes every check we hold the liveness address up and
// answer the probe; when it does not, we withdraw the address, IP-Link goes
// Down, the PBR rule stops matching, and office traffic returns to normal
// routing on its own.
//
// # Division of labour with dataplane/assert.go
//
// assert.go already asserts the TPROXY objects every 30s AND repairs them.
// The watchdog deliberately does not duplicate that check — it reads
// assert.go's snapshot. If both acted, they would fight: rules get flushed →
// watchdog withdraws the liveness address → firewall cuts over → assert
// repairs the rules → address comes back → firewall cuts back. So:
//
//	assert.go   repairs what was broken
//	watchdog    reports whether anything is broken, and acts only after the
//	            verdict has been stable for several rounds
//
// This is also why the watchdog's thresholds are consecutive-round counters
// rather than a single sample: assert.go may fix a transient flush before the
// watchdog's next tick, and one failed tick is not a verdict.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// State is the reported health of the data path.
type State string

const (
	// StateHealthy means every enabled check passed for RecoverThreshold
	// consecutive rounds and the liveness address is (or should be) up.
	StateHealthy State = "healthy"
	// StateUnhealthy means at least one check failed for FailThreshold
	// consecutive rounds. Under AutoFailover the liveness address has been
	// withdrawn by the time this state is published.
	StateUnhealthy State = "unhealthy"
	// StateUnknown is the state before the first round completes.
	StateUnknown State = "unknown"
)

// CheckName identifies a self-check in status output and alerts. Stable
// strings — operators grep for them.
type CheckName string

const (
	CheckEngineAlive    CheckName = "engine_alive"
	CheckDataplaneRules CheckName = "dataplane_rules"
	CheckPoolHealthy    CheckName = "pool_healthy"
	CheckEgressProbe    CheckName = "egress_probe"
	CheckDNSResolve     CheckName = "dns_resolve"
)

// CheckResult is one check's outcome for one round.
type CheckResult struct {
	Name CheckName `json:"name"`
	OK   bool      `json:"ok"`
	// Skipped marks a check that could not run meaningfully this round —
	// e.g. the egress probe when no proxy listener is reachable yet.
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// Status is the watchdog's published view, surfaced by GET /api/watchdog/status
// and included in the console's health card.
type Status struct {
	// Enabled is always true on a live watchdog. The field exists so every
	// response of GET /api/watchdog/status has the same shape: the disabled
	// case is published as {"enabled": false, "detail": ...}, and a consumer
	// checking `!enabled` must not read a missing field as disabled.
	Enabled bool      `json:"enabled"`
	State   State     `json:"state"`
	At      time.Time `json:"at"`

	// Checks is the most recent round's per-check outcome.
	Checks []CheckResult `json:"checks"`

	// Failing lists the names of checks that failed in the most recent round,
	// so a consumer does not have to re-derive it.
	Failing []CheckName `json:"failing"`

	// Consecutive counters behind the verdict.
	FailStreak       int `json:"fail_streak"`
	OKStreak         int `json:"ok_streak"`
	FailThreshold    int `json:"fail_threshold"`
	RecoverThreshold int `json:"recover_threshold"`

	// LivenessIP is the address whose presence signals the firewall.
	LivenessIP string `json:"liveness_ip"`
	// LivenessUp reports whether the address is currently held by this host.
	LivenessUp bool `json:"liveness_up"`
	// AutoFailover mirrors the config switch, so a reader can tell whether a
	// Down verdict would actually cause a cutover.
	AutoFailover bool `json:"auto_failover"`

	// LastTransition is when State last changed. Zero until it changes once.
	LastTransition time.Time `json:"last_transition,omitempty"`
	// LastError carries the most recent actionable failure detail.
	LastError string `json:"last_error,omitempty"`
}

// Checker runs one self-check. Implementations must be safe for repeated
// calls and should not block longer than roughly the watchdog interval.
type Checker interface {
	Name() CheckName
	Check(ctx context.Context) CheckResult
}

// Emitter reports a health transition to the operator. Wired to
// notify.Notifier in production; nil is safe (transitions are still logged).
type Emitter func(subject, body string, urgent bool)

// AddressManager controls the liveness address's presence in the kernel.
// Abstracted so the watchdog is testable without root or real interfaces.
type AddressManager interface {
	// Up ensures addr is configured on iface. Idempotent.
	Up(ctx context.Context) error
	// Down removes addr from iface. Idempotent — removing an address that is
	// not present is not an error.
	Down(ctx context.Context) error
	// Present reports whether the address is currently configured.
	Present(ctx context.Context) (bool, error)
}

// Watchdog runs the self-checks on a ticker and maintains the liveness
// address according to the verdict.
type Watchdog struct {
	cfg      config.WatchdogConfig
	checkers []Checker
	addr     AddressManager
	emit     Emitter

	mu     sync.RWMutex
	status Status
	// lastAlerted tracks per-check alert state so a persistently failing
	// check alerts on transition rather than every interval. Same pattern as
	// dataplane.Asserter.
	lastAlerted map[CheckName]bool
}

// New builds a Watchdog. Returns nil when the watchdog is disabled or
// unconfigured — callers should `if wd != nil` guard, matching the asserter.
//
// A nil return is also the correct behaviour when LivenessIP is empty: the
// config comment explains why that has no default, and a watchdog that
// withdrew an unset address would be reporting on nothing. install.sh
// refuses to deploy without it, so reaching here empty means a hand-edited
// config; log loudly rather than guess an address.
func New(cfg config.WatchdogConfig, checkers []Checker, addr AddressManager, emit Emitter) *Watchdog {
	if !cfg.IsEnabled() {
		slog.Info("watchdog: disabled by config")
		return nil
	}
	if cfg.LivenessIP == "" {
		slog.Warn("watchdog: no liveness_ip configured — not starting. " +
			"The firewall's IP-Link probe has nothing to observe, so the node " +
			"cannot signal its own health. Set watchdog.liveness_ip.")
		return nil
	}
	if addr == nil {
		slog.Warn("watchdog: no address manager — not starting")
		return nil
	}
	return &Watchdog{
		cfg:         cfg,
		checkers:    checkers,
		addr:        addr,
		emit:        emit,
		lastAlerted: map[CheckName]bool{},
		status: Status{
			Enabled:          true,
			State:            StateUnknown,
			LivenessIP:       cfg.LivenessIP,
			FailThreshold:    cfg.FailThreshold,
			RecoverThreshold: cfg.RecoverThreshold,
			AutoFailover:     cfg.AutoFailover,
		},
	}
}

// Status returns the latest published status safely.
func (w *Watchdog) Status() Status {
	w.mu.RLock()
	defer w.mu.RUnlock()
	s := w.status
	s.Checks = append([]CheckResult(nil), w.status.Checks...)
	s.Failing = append([]CheckName(nil), w.status.Failing...)
	return s
}

// Run blocks, evaluating every Interval until ctx is cancelled. The first
// round runs immediately so a node that comes up broken reports at once
// instead of one interval later.
func (w *Watchdog) Run(ctx context.Context) {
	interval := w.cfg.Interval
	if interval <= 0 {
		interval = 10 * time.Second
	}
	slog.Info("watchdog: starting",
		"interval", interval,
		"fail_threshold", w.cfg.FailThreshold,
		"recover_threshold", w.cfg.RecoverThreshold,
		"liveness_ip", w.cfg.LivenessIP,
		"auto_failover", w.cfg.AutoFailover)

	// Establish the initial kernel state so LivenessUp is truthful from the
	// first status read, even before the first round.
	if present, err := w.addr.Present(ctx); err == nil {
		w.mu.Lock()
		w.status.LivenessUp = present
		w.mu.Unlock()
	}

	w.tick(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick(ctx)
		}
	}
}

// tick runs one evaluation round: run checks, update counters, decide, act.
func (w *Watchdog) tick(ctx context.Context) {
	results := make([]CheckResult, 0, len(w.checkers))
	failing := make([]CheckName, 0, len(w.checkers))
	allOK := true
	for _, c := range w.checkers {
		r := c.Check(ctx)
		results = append(results, r)
		if !r.OK && !r.Skipped {
			allOK = false
			failing = append(failing, r.Name)
		}
	}

	w.mu.Lock()
	w.status.At = time.Now()
	w.status.Checks = results
	w.status.Failing = failing
	if allOK {
		w.status.OKStreak++
		w.status.FailStreak = 0
	} else {
		w.status.FailStreak++
		w.status.OKStreak = 0
		// Keep the first failing check's detail: it is the actionable one.
		for _, r := range results {
			if !r.OK && !r.Skipped {
				w.status.LastError = string(r.Name) + ": " + r.Detail
				break
			}
		}
	}
	failStreak := w.status.FailStreak
	okStreak := w.status.OKStreak
	cur := w.status.State
	w.mu.Unlock()

	// Verdict. Thresholds are consecutive-round counters, not single samples:
	// assert.go may repair a transient rule loss before our next tick.
	switch {
	case allOK && okStreak >= w.cfg.RecoverThreshold && cur != StateHealthy:
		w.transition(ctx, StateHealthy, results)
	case !allOK && failStreak >= w.cfg.FailThreshold && cur != StateUnhealthy:
		w.transition(ctx, StateUnhealthy, results)
	}

	// Alert on per-check transitions. Independent of the overall verdict so
	// a single flapping check is visible even while the verdict is unchanged.
	w.alertOnCheckTransitions(results)
}

// transition applies a verdict change: move the liveness address, publish the
// new state, and notify.
func (w *Watchdog) transition(ctx context.Context, next State, results []CheckResult) {
	w.mu.Lock()
	w.status.State = next
	w.status.LastTransition = time.Now()
	failing := append([]CheckName(nil), w.status.Failing...)
	lastErr := w.status.LastError
	autoFailover := w.cfg.AutoFailover
	w.mu.Unlock()

	slog.Warn("watchdog: health transition",
		"state", string(next), "failing", failing, "detail", lastErr)

	// Act on the kernel only in the unhealthy direction. Recovery puts the
	// address back so the firewall can divert again — that is the whole point
	// of the transition, and it is safe because we only get here after
	// RecoverThreshold consecutive clean rounds.
	var err error
	switch next {
	case StateUnhealthy:
		if !autoFailover {
			slog.Warn("watchdog: UNHEALTHY but auto_failover=false — reporting only. " +
				"The firewall keeps diverting; cut over manually if traffic is impacted.")
			break
		}
		err = w.addr.Down(ctx)
		if err != nil {
			slog.Error("watchdog: failed to withdraw liveness address", "err", err)
		}
	case StateHealthy:
		err = w.addr.Up(ctx)
		if err != nil {
			slog.Error("watchdog: failed to restore liveness address", "err", err)
		}
	}

	present, perr := w.addr.Present(ctx)
	if perr != nil {
		slog.Warn("watchdog: cannot read liveness address state", "err", perr)
	} else {
		w.mu.Lock()
		w.status.LivenessUp = present
		w.mu.Unlock()
	}

	w.notifyTransition(next, failing, lastErr, err)
}

// notifyTransition emits a transition message naming the failing checks, so
// the operator knows where to look before they log in.
func (w *Watchdog) notifyTransition(next State, failing []CheckName, detail string, actionErr error) {
	if !w.cfg.ShouldNotify() || w.emit == nil {
		return
	}
	subject := fmt.Sprintf("bypass node health: %s", next)
	body := fmt.Sprintf("liveness_ip=%s auto_failover=%t", w.cfg.LivenessIP, w.cfg.AutoFailover)
	if len(failing) > 0 {
		body += "\nfailing checks: " + joinNames(failing)
	}
	if detail != "" {
		body += "\ndetail: " + detail
	}
	if actionErr != nil {
		body += "\n⚠️ could not apply the address change: " + actionErr.Error()
	} else if next == StateUnhealthy && !w.cfg.AutoFailover {
		body += "\n(no automatic cutover — auto_failover is false)"
	}
	// Unhealthy is urgent; recovery is informational.
	w.emit(subject, body, next == StateUnhealthy)
}

// alertOnCheckTransitions emits per-check transition alerts, mirroring
// dataplane.Asserter's behaviour so a recurring single-check failure is
// visible without flooding.
func (w *Watchdog) alertOnCheckTransitions(results []CheckResult) {
	if w.emit == nil {
		return
	}
	for _, r := range results {
		if r.Skipped {
			continue
		}
		failing := !r.OK
		w.mu.Lock()
		was := w.lastAlerted[r.Name]
		if failing != was {
			w.lastAlerted[r.Name] = failing
		}
		w.mu.Unlock()
		if failing == was {
			continue
		}
		if failing {
			w.emit(
				fmt.Sprintf("bypass node check %s: FAILED", r.Name),
				fmt.Sprintf("%s\nliveness_ip=%s", r.Detail, w.cfg.LivenessIP),
				true,
			)
		} else {
			w.emit(
				fmt.Sprintf("bypass node check %s: recovered", r.Name),
				r.Detail,
				false,
			)
		}
	}
}

func joinNames(names []CheckName) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += string(n)
	}
	return out
}
