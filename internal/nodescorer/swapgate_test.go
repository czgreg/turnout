// The swap threshold is the pool's only anti-flap gate, and it has to apply
// to the FINAL membership, not just to the preferred-set filter. Measured on
// 10.100.6.15 (2026-10-24): the K=8 pool and the next eight candidates were
// all within 263-300 long EWMA (1.4 points across the boundary), yet the pool
// swapped 2-12 times an hour. Each swap rotated the primary egress IP of
// ~21% of the /16's 1024 terminal buckets — for no measurable quality gain.
//
// Root cause: the kTarget fill post-pass re-admitted the challenger the
// threshold had just rejected, after the incumbent it displaced had already
// been evicted for leaving top-K.

package nodescorer

import (
	"context"
	"testing"
)

func poolSetEqual(got, want map[string]bool) bool {
	if len(got) != len(want) {
		return false
	}
	for k := range want {
		if !got[k] {
			return false
		}
	}
	return true
}

func TestSwapGate_NoSwapWithinThreshold(t *testing.T) {
	cfg := kGatingCfg(3)
	cfg.SwapThresholdScore = 400
	nodes := map[string]proxyNode{
		"sub/n1": {alive: true, history: goodHistory(100)},
		"sub/n2": {alive: true, history: goodHistory(100)},
		"sub/n3": {alive: true, history: goodHistory(100)},
		"sub/n4": {alive: true, history: goodHistory(100)},
	}
	s, _, _ := newDecisionScorer(t, cfg, nodes)
	// n4 outranks the marginal incumbent n3, but by 7 points — well inside
	// the 400-point gate. Mirrors the live boundary (282.2 vs 283.6).
	seedEWMA(s, "sub/n1", 200, 280)
	seedEWMA(s, "sub/n2", 200, 282)
	seedEWMA(s, "sub/n3", 200, 290)
	seedEWMA(s, "sub/n4", 200, 283)
	s.poolSet = map[string]bool{"sub/n1": true, "sub/n2": true, "sub/n3": true}

	s.score(context.Background())

	got := inPoolNames(s.GetSnapshot())
	want := map[string]bool{"sub/n1": true, "sub/n2": true, "sub/n3": true}
	if !poolSetEqual(got, want) {
		t.Errorf("pool = %v, want unchanged %v (no challenger clears the 400-point margin)", got, want)
	}
}

func TestSwapGate_SwapsWhenMarginCleared(t *testing.T) {
	cfg := kGatingCfg(3)
	cfg.SwapThresholdScore = 400
	nodes := map[string]proxyNode{
		"sub/n1": {alive: true, history: goodHistory(100)},
		"sub/n2": {alive: true, history: goodHistory(100)},
		"sub/n3": {alive: true, history: goodHistory(100)},
		"sub/n4": {alive: true, history: goodHistory(100)},
	}
	s, _, _ := newDecisionScorer(t, cfg, nodes)
	// n3 has degraded to 900; n4 is 500 points better, clearing the gate.
	seedEWMA(s, "sub/n1", 200, 280)
	seedEWMA(s, "sub/n2", 200, 282)
	seedEWMA(s, "sub/n3", 200, 900)
	seedEWMA(s, "sub/n4", 200, 300)
	s.poolSet = map[string]bool{"sub/n1": true, "sub/n2": true, "sub/n3": true}

	s.score(context.Background())

	got := inPoolNames(s.GetSnapshot())
	want := map[string]bool{"sub/n1": true, "sub/n2": true, "sub/n4": true}
	if !poolSetEqual(got, want) {
		t.Errorf("pool = %v, want %v (n4 clears the margin and must replace n3)", got, want)
	}
}

// Incumbency protection must never keep a node that failed the liveness gate.
// The swap margin damps QUALITY churn; hard failures (fail_rate >= 0.9) are a
// different signal and have to evict immediately.
func TestSwapGate_UnqualifiedIncumbentStillEvicted(t *testing.T) {
	cfg := kGatingCfg(4)
	cfg.SwapThresholdScore = 400
	nodes := map[string]proxyNode{
		"sub/n1": {alive: true, history: goodHistory(100)},
		"sub/n2": {alive: true, history: goodHistory(100)},
		"sub/n3": {alive: true, history: goodHistory(100)},
		// 10/10 probes failed → fail_rate 1.0 → Qualified=false.
		"sub/n4": {alive: false, history: partialFailHistory(10, 300)},
	}
	s, _, _ := newDecisionScorer(t, cfg, nodes)
	seedEWMA(s, "sub/n1", 200, 280)
	seedEWMA(s, "sub/n2", 200, 282)
	seedEWMA(s, "sub/n3", 200, 284)
	seedEWMA(s, "sub/n4", 200, 286)
	s.poolSet = map[string]bool{
		"sub/n1": true, "sub/n2": true, "sub/n3": true, "sub/n4": true,
	}

	s.score(context.Background())

	got := inPoolNames(s.GetSnapshot())
	want := map[string]bool{"sub/n1": true, "sub/n2": true, "sub/n3": true}
	if !poolSetEqual(got, want) {
		t.Errorf("pool = %v, want %v (a hard-failed incumbent must not be protected by the margin)", got, want)
	}
}
