package nodescorer

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

func TestServerHosts_Normalizes(t *testing.T) {
	got := serverHosts([]subscribe.Outbound{
		{"tag": "a", "server": " Relay.Example.COM. "},
		{"tag": "b", "server": "1.2.3.4"},
		{"tag": "c"},                 // no server
		{"server": "orphan.example"}, // no tag
	})
	want := map[string]string{"a": "relay.example.com", "b": "1.2.3.4"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
}

func TestApplyEndpointPenalties(t *testing.T) {
	node := func(name string, alive bool, fail float64, probes int) NodeHealth {
		return NodeHealth{Name: name, Alive: alive, FailRate: fail, ProbeCount: probes}
	}
	nodes := []NodeHealth{
		// relay: 4 live nodes at 1/8 fail → pooled 4/32 = 0.125 → 625.
		node("m/1", true, 0.125, 8),
		node("m/2", true, 0.125, 8),
		node("m/3", true, 0.125, 8),
		node("m/4", true, 0.125, 8),
		// dead sibling on the same relay: excluded from the pool but still
		// carries the penalty (it must not be promoted in their place).
		node("m/dead", false, 1.0, 8),
		// unmeasured sibling: no contribution, still penalized.
		node("m/new", true, 0, 0),
		// clean host with enough nodes: zero penalty, not in the map.
		node("h/1", true, 0, 10),
		node("h/2", true, 0, 10),
		node("h/3", true, 0, 10),
		// two-node host: too few nodes to judge even though it fails a lot.
		node("w/1", true, 0.5, 10),
		node("w/2", true, 0.5, 10),
		// node with no known server.
		node("x/1", true, 0.5, 10),
	}
	hostOf := map[string]string{
		"m/1": "relay", "m/2": "relay", "m/3": "relay", "m/4": "relay",
		"m/dead": "relay", "m/new": "relay",
		"h/1": "hutao", "h/2": "hutao", "h/3": "hutao",
		"w/1": "wodi", "w/2": "wodi",
	}
	pen := applyEndpointPenalties(nodes, hostOf)

	for _, name := range []string{"m/1", "m/2", "m/3", "m/4", "m/dead", "m/new"} {
		if math.Abs(pen[name]-625) > 1e-9 {
			t.Errorf("%s: penalty %v, want 625", name, pen[name])
		}
	}
	for _, name := range []string{"h/1", "w/1", "w/2", "x/1"} {
		if _, ok := pen[name]; ok {
			t.Errorf("%s: unexpected penalty %v", name, pen[name])
		}
	}
	if nodes[0].Endpoint != "relay" || nodes[0].EndpointFailRate != 0.125 || nodes[0].EndpointPenalty != 625 {
		t.Errorf("m/1 health fields not filled: %+v", nodes[0])
	}
	if nodes[11].Endpoint != "" {
		t.Errorf("x/1 should have no endpoint, got %q", nodes[11].Endpoint)
	}
}

// TestApplyEndpointPenalties_TooFewProbes: 3 nodes with 6 probes each is 18
// samples — below endpointMinProbes, so no judgement.
func TestApplyEndpointPenalties_TooFewProbes(t *testing.T) {
	nodes := []NodeHealth{
		{Name: "a", Alive: true, FailRate: 1.0 / 6, ProbeCount: 6},
		{Name: "b", Alive: true, FailRate: 1.0 / 6, ProbeCount: 6},
		{Name: "c", Alive: true, FailRate: 1.0 / 6, ProbeCount: 6},
	}
	pen := applyEndpointPenalties(nodes, map[string]string{"a": "r", "b": "r", "c": "r"})
	if len(pen) != 0 {
		t.Fatalf("expected no penalty below %d samples, got %v", endpointMinProbes, pen)
	}
}

// TestDecision_SharedEndpointFailurePushesRelayOut reproduces 2026-11-23 on
// 10.100.6.15: every K-gated pool member sat on one relay hostname whose DNS
// pool was a third dead. Each node lost ~1 probe in 8 — individually too
// little to lose its slot to a clean but slower node — yet a tenth of real
// connections stalled. Pooled per endpoint, the penalty must swap the relay
// nodes out in the same round, keep them out while the relay keeps failing,
// and let them back once it recovers.
func TestDecision_SharedEndpointFailurePushesRelayOut(t *testing.T) {
	cfg := kGatingCfg(4)
	cfg.HotReloadMinInterval = 0
	cfg.TrialDuration = time.Nanosecond // production runs 5m; keep challengers promotable
	cfg.SwapThresholdScore = 100

	nodes := map[string]proxyNode{}
	var outbounds []subscribe.Outbound
	for i := 1; i <= 6; i++ {
		tag := fmt.Sprintf("momo/HK%d_LL", i)
		nodes[tag] = proxyNode{alive: true, history: goodHistory(45)}
		outbounds = append(outbounds, subscribe.Outbound{"tag": tag, "server": "liulian-node.example"})
	}
	for i := 1; i <= 4; i++ {
		tag := fmt.Sprintf("hutao/JP%d", i)
		nodes[tag] = proxyNode{alive: true, history: goodHistory(400)}
		outbounds = append(outbounds, subscribe.Outbound{"tag": tag, "server": "hutao.example"})
	}

	const probeURL = "http://probe.test/generate_204"
	apiAddr, mutate := mockClashAPI(t, probeURL, nodes)
	fr := &fakeRenderer{path: t.TempDir() + "/config.yaml"}
	s := New(cfg, nil, apiAddr, "", probeURL, "", fr, func() []subscribe.Outbound { return outbounds })
	t.Cleanup(func() { time.Sleep(50 * time.Millisecond) })

	countLL := func(pool map[string]bool) int {
		n := 0
		for name := range pool {
			if name[:4] == "momo" {
				n++
			}
		}
		return n
	}

	// Round 1: relay healthy — the fast relay nodes take all 4 slots.
	s.score(context.Background())
	if got := inPoolNames(s.GetSnapshot()); len(got) != 4 || countLL(got) != 4 {
		t.Fatalf("round1: want 4 relay nodes in pool, got %v", got)
	}

	// Round 2: the relay drops 1 probe in 10 on every node.
	for i := 1; i <= 6; i++ {
		mutate(fmt.Sprintf("momo/HK%d_LL", i), partialFailHistory(1, 45))
	}
	s.score(context.Background())
	snap := s.GetSnapshot()
	if got := inPoolNames(snap); len(got) != 4 || countLL(got) != 0 {
		t.Fatalf("round2: relay nodes should all be swapped out for hutao, got %v", got)
	}
	for _, n := range snap.Nodes {
		if n.Name == "momo/HK1_LL" && (n.Endpoint != "liulian-node.example" || n.EndpointPenalty < 400) {
			t.Errorf("round2: HK1 endpoint fields not surfaced: endpoint=%q penalty=%v", n.Endpoint, n.EndpointPenalty)
		}
	}

	// Round 3: still failing — no flap back.
	s.score(context.Background())
	if got := inPoolNames(s.GetSnapshot()); countLL(got) != 0 {
		t.Fatalf("round3: relay nodes must stay out while the relay fails, got %v", got)
	}

	// Round 4: relay recovers — the penalty lifts and the relay nodes win
	// their slots back on their (untouched) EWMA.
	for i := 1; i <= 6; i++ {
		mutate(fmt.Sprintf("momo/HK%d_LL", i), goodHistory(45))
	}
	s.score(context.Background())
	if got := inPoolNames(s.GetSnapshot()); countLL(got) != 4 {
		t.Fatalf("round4: relay nodes should return after recovery, got %v", got)
	}
}
