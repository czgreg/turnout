// Named-pool changes are coalesced: a membership proposed by one scoring
// round is applied only after a second consecutive round confirms it, unless
// a removed member is dead. Measured on 10.100.6.15 (2026-10-24/25): 8 of 12
// steady-state reloads were ai-pool-only swaps clustered in 10-15 minute
// windows; each rebuilt all 68 groups and cleared the DNS cache while the
// default routing set was unchanged.

package nodescorer

import (
	"context"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// hotReload runs on a goroutine; wait for the render it schedules.
func waitRenders(t *testing.T, fr *fakeRenderer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		fr.mu.Lock()
		n := fr.renders
		fr.mu.Unlock()
		if n >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	fr.mu.Lock()
	n := fr.renders
	fr.mu.Unlock()
	t.Fatalf("renders = %d, want %d", n, want)
}

func namedPoolScorer(t *testing.T, bAlive bool) (*Scorer, *fakeRenderer) {
	t.Helper()
	cfg := kGatingCfg(3)
	cfg.SwapThresholdScore = 0 // isolate coalescing from the quality margin
	nodes := map[string]proxyNode{
		"sub/US-A": {alive: true, history: goodHistory(100)},
		"sub/US-B": {alive: bAlive, history: goodHistory(100)},
		"sub/US-C": {alive: true, history: goodHistory(100)},
	}
	s, fr, _ := newDecisionScorer(t, cfg, nodes)
	s.pools = []config.PoolConfig{{Name: "ai-pool", NodePattern: "US", Size: 2}}
	seedEWMA(s, "sub/US-A", 200, 300)
	seedEWMA(s, "sub/US-B", 200, 300)
	seedEWMA(s, "sub/US-C", 200, 100) // clearly better than the incumbents
	// Steady state: default routing and probing sets already applied.
	s.poolSet = map[string]bool{"sub/US-A": true, "sub/US-B": true, "sub/US-C": true}
	s.lastDefaultPoolRendered = map[string]bool{
		"sub/US-A": true, "sub/US-B": true, "sub/US-C": true,
	}
	s.poolMembers = map[string][]string{"ai-pool": {"sub/US-A", "sub/US-B"}}
	return s, fr
}

func memberSet(s *Scorer, pool string) map[string]bool {
	out := map[string]bool{}
	for _, m := range s.poolMembers[pool] {
		out[m] = true
	}
	return out
}

func TestNamedPoolChange_DeferredThenApplied(t *testing.T) {
	s, fr := namedPoolScorer(t, true)

	s.score(context.Background())
	if memberSet(s, "ai-pool")["sub/US-C"] {
		t.Fatal("named-pool change applied on the first round; expected one-round confirmation")
	}
	if s.pendingNamedMembers == nil {
		t.Error("no pending named-pool membership recorded")
	}
	if fr.renders != 0 {
		t.Errorf("renders after deferred round = %d, want 0", fr.renders)
	}

	s.score(context.Background())
	if !memberSet(s, "ai-pool")["sub/US-C"] {
		t.Errorf("named-pool change not applied after confirmation; pool=%v", s.poolMembers["ai-pool"])
	}
	if s.pendingNamedMembers != nil {
		t.Error("pending membership not cleared after apply")
	}
	waitRenders(t, fr, 1)
}

func TestNamedPoolChange_DeadIncumbentAppliedImmediately(t *testing.T) {
	s, fr := namedPoolScorer(t, false)

	s.score(context.Background())
	if memberSet(s, "ai-pool")["sub/US-B"] {
		t.Errorf("dead incumbent still in ai-pool: %v", s.poolMembers["ai-pool"])
	}
	if !memberSet(s, "ai-pool")["sub/US-C"] {
		t.Errorf("replacement not applied: %v", s.poolMembers["ai-pool"])
	}
	if s.pendingNamedMembers != nil {
		t.Error("dead-member removal must not be left pending")
	}
	waitRenders(t, fr, 1)
}
