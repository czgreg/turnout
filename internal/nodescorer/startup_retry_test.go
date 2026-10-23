// Startup scoring must not be a one-shot. After a restart mihomo may still be
// applying the rendered config (its /proxies map can be empty or partial while
// it loads) and the first subscription refresh may not have landed, so the
// 10s-warm-up round can find no candidates. Before 2026-10-23 that miss was
// silent and the next attempt waited a full ScoringInterval — measured on
// 10.100.6.15 after every redeploy.

package nodescorer

import (
	"context"
	"testing"
)

func TestScore_ReturnsFalseWhenNoCandidates(t *testing.T) {
	s, _, _ := newDecisionScorer(t, defaultCfg(), nil)
	if s.score(context.Background()) {
		t.Error("score reported success with an empty default-pool and no discovery")
	}
}

func TestScore_ReturnsTrueWithCandidates(t *testing.T) {
	nodes := map[string]proxyNode{
		"sub/n1": {alive: true, history: goodHistory(100)},
	}
	s, _, _ := newDecisionScorer(t, defaultCfg(), nodes)
	if !s.score(context.Background()) {
		t.Error("score reported failure with a candidate present")
	}
}

// The ticker path ignores the result (a failed round just retries on the next
// interval), so the only behavioural contract here is that a failed round
// leaves no pool state behind.
func TestScore_FailedRoundLeavesPoolUnchanged(t *testing.T) {
	s, _, _ := newDecisionScorer(t, defaultCfg(), nil)
	s.poolSet = map[string]bool{"sub/kept": true}
	s.score(context.Background())
	if !s.poolSet["sub/kept"] || len(s.poolSet) != 1 {
		t.Errorf("failed round mutated poolSet: %v", s.poolSet)
	}
}
