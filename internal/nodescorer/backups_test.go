// Cross-subscription secondaries. The scorer publishes, per primary
// subscription, the best qualified+alive candidates from OTHER subscriptions;
// the renderer pairs each terminal's HRW primary with one of them. Measured on
// 10.100.6.15 (2026-10-24..27): 52 of 60 proxy failures in 24h fell in three
// single-subscription ingress incidents, with 99.4% of terminal pairs sharing
// that subscription.

package nodescorer

import (
	"context"
	"testing"
)

// backupScorer: routing K=3 (KMin) entirely on subscription "a", with "b"
// as the other subscription. Steady state is pre-applied so changes read as
// named-only; the b nodes are within the 400-point swap margin of the worst
// incumbent, so routing stays on a.
func backupScorer(t *testing.T, b1Alive bool) (*Scorer, *fakeRenderer) {
	t.Helper()
	cfg := kGatingCfg(3)
	cfg.SwapThresholdScore = 400
	nodes := map[string]proxyNode{
		"a/n1": {alive: true, history: goodHistory(100)},
		"a/n2": {alive: true, history: goodHistory(100)},
		"a/n3": {alive: true, history: goodHistory(100)},
		"b/n1": {alive: b1Alive, history: goodHistory(100)},
		"b/n2": {alive: true, history: goodHistory(100)},
	}
	s, fr, _ := newDecisionScorer(t, cfg, nodes)
	seedEWMA(s, "a/n1", 100, 100)
	seedEWMA(s, "a/n2", 100, 110)
	seedEWMA(s, "a/n3", 100, 120)
	seedEWMA(s, "b/n1", 100, 300)
	seedEWMA(s, "b/n2", 100, 320)
	all := map[string]bool{"a/n1": true, "a/n2": true, "a/n3": true, "b/n1": true, "b/n2": true}
	s.poolSet = map[string]bool{"a/n1": true, "a/n2": true, "a/n3": true}
	s.lastDefaultPoolRendered = all
	return s, fr
}

func TestComputeBackups_CrossSubscriptionOnly(t *testing.T) {
	s, _ := backupScorer(t, true)
	s.score(context.Background()) // proposes backups (deferred, round 1)
	s.score(context.Background()) // confirms → applied

	alts := s.backups[backupClassDefault]["a"]
	if len(alts) != 2 {
		t.Fatalf("backups for a = %v, want both b nodes", alts)
	}
	for _, n := range alts {
		if subscriptionOf(n) == "a" {
			t.Errorf("backup %s is in the primary's own subscription", n)
		}
	}
	if _, ok := s.backups[backupClassDefault]["b"]; ok {
		t.Error("no routing member is on b, so b needs no backups entry")
	}
}

func TestComputeBackups_ExcludesDeadNodes(t *testing.T) {
	s, _ := backupScorer(t, false) // b/n1 alive=false
	s.score(context.Background())
	s.score(context.Background())
	for _, n := range s.backups[backupClassDefault]["a"] {
		if n == "b/n1" {
			t.Fatal("dead node chosen as a backup")
		}
	}
}

func TestBackupsOnlyChange_IsCoalesced(t *testing.T) {
	s, fr := backupScorer(t, true)

	s.score(context.Background())
	if s.backups != nil {
		t.Fatalf("backups applied on the first proposal: %v", s.backups)
	}
	fr.mu.Lock()
	early := fr.renders
	fr.mu.Unlock()
	if early != 0 {
		t.Fatalf("backups-only change reloaded immediately (renders=%d)", early)
	}

	s.score(context.Background())
	if len(s.backups[backupClassDefault]["a"]) == 0 {
		t.Fatal("backups not applied after confirmation")
	}
	waitRenders(t, fr, 1)
	fr.mu.Lock()
	got := fr.lastBackups
	fr.mu.Unlock()
	if len(got[backupClassDefault]["a"]) == 0 {
		t.Errorf("render did not receive backups: %v", got)
	}
}

func TestBackupSelection_Sticky(t *testing.T) {
	s, _ := backupScorer(t, true)
	// b/n1 (long 300) is 20 points better than incumbent b/n2 (320); the
	// 400-point margin must keep the incumbent, so backups do not churn on
	// EWMA noise and cause reloads.
	eligible := []NodeHealth{{Name: "b/n1"}, {Name: "b/n2"}} // best-first
	if got := s.stickyTopN([]string{"b/n2"}, eligible, 1); len(got) != 1 || got[0] != "b/n2" {
		t.Errorf("sticky pick = %v, want incumbent [b/n2]", got)
	}
	// Without an incumbent the best candidate wins.
	if got := s.stickyTopN(nil, eligible, 1); len(got) != 1 || got[0] != "b/n1" {
		t.Errorf("fresh pick = %v, want [b/n1]", got)
	}
}

// Right after a mihomo restart every proxy reads alive=true with empty
// history. A backup must have been measured: on 10.100.6.15 (2026-10-27
// 14:20) the first round picked three momo nodes from a subscription with no
// remaining quota, and dns-out failed 12 dials until the next round dropped
// them.
func TestComputeBackups_RequiresProbeHistory(t *testing.T) {
	s, _ := backupScorer(t, true)
	nodes := []NodeHealth{
		{Name: "b/fresh", Qualified: true, Alive: true, ProbeCount: 0},
		{Name: "b/measured", Qualified: true, Alive: true, ProbeCount: 5},
	}
	q := []*NodeHealth{&nodes[0], &nodes[1]}
	got := s.computeBackups(nodes, q, []string{"a/n1"}, nil)[backupClassDefault]["a"]
	if len(got) != 1 || got[0] != "b/measured" {
		t.Errorf("backups = %v, want only the measured node", got)
	}
	nodes[1].ProbeCount = 0
	if b := s.computeBackups(nodes, q, []string{"a/n1"}, nil); b != nil {
		t.Errorf("with no measured foreign node backups must be empty (legacy pairing), got %v", b)
	}
}
