package nodescorer

// Tests for legacy-mode fail eviction (failEvictRate / failEvictRounds).
// The gap it closes: a member failing 50-89% of probes stays Qualified, its
// long EWMA barely moves within an hour, and the short-EWMA fast-evict is
// relative to a pool median that rises with it — so on 10.100.6.15
// (2026-11-26) hutao members sat in the pool at fail 0.6-0.83 for an hour.

import (
	"context"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// failingHistory has fail_rate 0.6 over 10 samples, with a success in the
// last 5 (so scoreNode keeps it Qualified) and a low RTT on the successes
// (so neither the composite ceiling nor latency explains an eviction).
func failingHistory(rttMs int) []int {
	return []int{rttMs, 0, rttMs, 0, 0, rttMs, 0, 0, rttMs, 0}
}

func fiveNodePool() map[string]proxyNode {
	return map[string]proxyNode{
		"sub/n1": {alive: true, history: goodHistory(100)},
		"sub/n2": {alive: true, history: goodHistory(120)},
		"sub/n3": {alive: true, history: goodHistory(140)},
		"sub/n4": {alive: true, history: goodHistory(160)},
		"sub/n5": {alive: true, history: goodHistory(180)}, // spare
	}
}

func failEvictCfg() config.NodeQualifyConfig {
	cfg := kGatingCfg(4)
	cfg.HotReloadMinInterval = 0
	return cfg
}

func TestFailEvict_MemberEvictedAfterTwoRounds(t *testing.T) {
	s, _, mutate := newDecisionScorer(t, failEvictCfg(), fiveNodePool())
	s.score(context.Background())
	if got := inPoolNames(s.GetSnapshot()); !got["sub/n4"] || len(got) != 4 {
		t.Fatalf("round1: expected n4 in a 4-node pool; got %v", got)
	}

	mutate("sub/n4", failingHistory(160))
	s.score(context.Background())
	if got := inPoolNames(s.GetSnapshot()); !got["sub/n4"] {
		t.Fatalf("round2: one failing round must not evict (noise guard); pool=%v", got)
	}

	s.score(context.Background())
	got := inPoolNames(s.GetSnapshot())
	if got["sub/n4"] {
		t.Errorf("round3: n4 at fail 0.6 for 2 rounds must be evicted; pool=%v", got)
	}
	if !got["sub/n5"] || len(got) != 4 {
		t.Errorf("round3: spare n5 should backfill to K=4; pool=%v", got)
	}
}

func TestFailEvict_RecoveryRoundResetsStreak(t *testing.T) {
	s, _, mutate := newDecisionScorer(t, failEvictCfg(), fiveNodePool())
	s.score(context.Background())
	for i, h := range [][]int{failingHistory(160), goodHistory(160), failingHistory(160)} {
		mutate("sub/n4", h)
		s.score(context.Background())
		if got := inPoolNames(s.GetSnapshot()); !got["sub/n4"] {
			t.Fatalf("round %d: non-consecutive failing rounds must not evict; pool=%v", i+2, got)
		}
	}
}

// Two samples can only read 0 / 0.5 / 1.0; 0.5 there is one lost probe.
func TestFailEvict_TooFewSamplesNeverCounts(t *testing.T) {
	s, _, mutate := newDecisionScorer(t, failEvictCfg(), fiveNodePool())
	s.score(context.Background())
	mutate("sub/n4", []int{0, 160})
	for i := 0; i < 4; i++ {
		s.score(context.Background())
	}
	if got := inPoolNames(s.GetSnapshot()); !got["sub/n4"] {
		t.Errorf("2-sample fail 0.5 must not trigger eviction; pool=%v", got)
	}
}

// The whole pool degrades together (the 2026-11-26 shape). Eviction stops at
// the minPool floor (3 when unset), and the worst member goes first.
func TestFailEvict_CorrelatedFailureRespectsFloorWorstFirst(t *testing.T) {
	nodes := fiveNodePool()
	nodes["sub/n6"] = proxyNode{alive: true, history: goodHistory(190)}
	s, _, mutate := newDecisionScorer(t, failEvictCfg(), nodes)
	s.score(context.Background())
	before := inPoolNames(s.GetSnapshot())
	if len(before) != 4 {
		t.Fatalf("round1: expected 4-node pool; got %v", before)
	}

	worst := ""
	for name := range before {
		if worst == "" || name > worst {
			worst = name
		}
	}
	for name := range before {
		h := failingHistory(150) // 0.6
		if name == worst {
			h = []int{150, 0, 0, 0, 0, 150, 0, 0, 150, 0} // 0.7
		}
		mutate(name, h)
	}
	s.score(context.Background())
	s.score(context.Background())

	got := inPoolNames(s.GetSnapshot())
	if got[worst] {
		t.Errorf("worst member %s (fail 0.7) should be the one evicted; pool=%v", worst, got)
	}
	kept := 0
	for name := range before {
		if got[name] {
			kept++
		}
	}
	if kept != 3 {
		t.Errorf("floor: expected 3 failing members kept (|pool| 4 - 1 = minPool 3), got %d; pool=%v", kept, got)
	}
	if len(got) != 4 {
		t.Errorf("a healthy spare should backfill to K=4; pool=%v", got)
	}
}
