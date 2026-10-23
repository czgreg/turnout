package nodescorer

import (
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

func buildProxyEntry(alive bool, probeURL string, delays []int) map[string]interface{} {
	history := make([]interface{}, len(delays))
	for i, d := range delays {
		history[i] = map[string]interface{}{
			"time":  "2026-06-05T00:00:00Z",
			"delay": float64(d),
		}
	}
	return map[string]interface{}{
		"alive": alive,
		"extra": map[string]interface{}{
			probeURL: map[string]interface{}{
				"alive":   alive,
				"history": history,
			},
		},
	}
}

func defaultCfg() config.NodeQualifyConfig {
	return config.NodeQualifyConfig{
		MaxRTTP50Ms:    500,
		MaxRTTP95Ms:    800,
		MaxJitterMs:    300,
		MaxFailRate:    0.25,
		MinProbes:      2,
		EvictStrikes:   2,
		ReadmitStrikes: 1,
	}
}

func newTestScorer(cfg config.NodeQualifyConfig) *Scorer {
	return &Scorer{
		probeURL:           "http://test",
		cfg:                cfg,
		probeResults:       map[string]map[string]ProbeResult{},
		probeLast:          map[string]map[string]time.Time{},
		rollbackQuarantine: map[string]time.Time{},
		poolSet:            map[string]bool{},
	}
}

// TestComputePoolMembers verifies probe-gated named-pool membership: only
// us-pool nodes that pass ALL of a pool's required probes are members; a
// node missing any required probe result (or failing it) is excluded.
func TestComputePoolMembers(t *testing.T) {
	s := newTestScorer(defaultCfg())
	s.pools = []config.PoolConfig{{
		Name:            "openai-pool",
		RequiresPassing: []string{"chatgpt.com", "claude.ai"},
		RuleSets:        []string{"geosite-openai"},
	}}
	// nodeA passes both → member. nodeB fails chatgpt (cf challenge) →
	// excluded. nodeC has no claude.ai result yet → excluded.
	// nodePassesProbes reads probeOKHistory (sliding window), not the
	// raw .OK on the latest result — populate both since storeProbeResult
	// keeps them in lockstep at runtime.
	s.probeResults = map[string]map[string]ProbeResult{
		"nodeA": {
			"chatgpt.com": {OK: true},
			"claude.ai":   {OK: true},
		},
		"nodeB": {
			"chatgpt.com": {OK: false, CFMitigated: true},
			"claude.ai":   {OK: true},
		},
		"nodeC": {
			"chatgpt.com": {OK: true},
		},
	}
	s.probeOKHistory = map[string]map[string][]bool{
		"nodeA": {
			"chatgpt.com": {true},
			"claude.ai":   {true},
		},
		"nodeB": {
			"chatgpt.com": {false},
			"claude.ai":   {true},
		},
		"nodeC": {
			"chatgpt.com": {true},
		},
	}
	usPool := map[string]bool{"nodeA": true, "nodeB": true, "nodeC": true}

	got := s.computePoolMembers(nil, usPool, 0)
	members := got["openai-pool"]
	if len(members) != 1 || members[0] != "nodeA" {
		t.Errorf("openai-pool members = %v, want [nodeA]", members)
	}
}

// TestComputePoolMembers_NoGating: a pool with empty RequiresPassing is not
// included in the explicit member map (renderer falls back to full us-pool).
func TestComputePoolMembers_NoGating(t *testing.T) {
	s := newTestScorer(defaultCfg())
	s.pools = []config.PoolConfig{{Name: "plain-pool", RuleSets: []string{"geosite-x"}}}
	got := s.computePoolMembers(nil, map[string]bool{"nodeA": true}, 0)
	if _, ok := got["plain-pool"]; ok {
		t.Error("ungated pool should not appear in poolMembers (renderer falls back to us-pool)")
	}
}

// TestComputePoolMembers_ClassPattern verifies a class pool takes only the
// nodes matching its own node_pattern, ranked by long EWMA and capped at
// Size. The global us-pool set is irrelevant for class pools.
func TestComputePoolMembers_ClassPattern(t *testing.T) {
	cfg := defaultCfg()
	cfg.SwapThresholdScore = 400
	s := newTestScorer(cfg)
	s.pools = []config.PoolConfig{{
		Name:        "ai-pool",
		NodePattern: `^us`,
		Size:        2,
		RuleSets:    []string{"geosite-openai"},
	}}
	s.poolMembers = map[string][]string{}
	now := time.Now()
	s.ewma = map[string]*nodeEWMA{
		"us1": {Long: ewmaPoint{Value: 100, UpdatedAt: now}},
		"us2": {Long: ewmaPoint{Value: 200, UpdatedAt: now}},
		"us3": {Long: ewmaPoint{Value: 300, UpdatedAt: now}},
		"jp1": {Long: ewmaPoint{Value: 50, UpdatedAt: now}},
		"us5": {Long: ewmaPoint{Value: 10, UpdatedAt: now}}, // best score, but dead
	}
	nodes := []NodeHealth{
		{Name: "us1", Qualified: true, Alive: true},
		{Name: "us2", Qualified: true, Alive: true},
		{Name: "us3", Qualified: true, Alive: true},
		{Name: "jp1", Qualified: true, Alive: true},
		{Name: "us4", Qualified: false, Alive: true}, // not qualified → never a member
		{Name: "us5", Qualified: true, Alive: false}, // dead → never a member
	}
	got := s.computePoolMembers(nodes, map[string]bool{"jp1": true}, 8)
	members := got["ai-pool"]
	if len(members) != 2 || members[0] != "us1" || members[1] != "us2" {
		t.Fatalf("ai-pool members = %v, want [us1 us2] (pattern + alive + size + EWMA rank)", members)
	}
}

// TestComputePoolMembers_ClassSticky pins the anti-flap rule: an incumbent
// keeps its slot unless a challenger beats the worst incumbent's long EWMA
// by SwapThresholdScore.
func TestComputePoolMembers_ClassSticky(t *testing.T) {
	cfg := defaultCfg()
	cfg.SwapThresholdScore = 400
	s := newTestScorer(cfg)
	s.pools = []config.PoolConfig{{
		Name:        "ai-pool",
		NodePattern: `^us`,
		Size:        2,
	}}
	now := time.Now()
	s.ewma = map[string]*nodeEWMA{
		"us1": {Long: ewmaPoint{Value: 100, UpdatedAt: now}},
		"us2": {Long: ewmaPoint{Value: 200, UpdatedAt: now}},
		"us3": {Long: ewmaPoint{Value: 300, UpdatedAt: now}},
	}
	s.poolMembers = map[string][]string{"ai-pool": {"us2", "us3"}}
	nodes := []NodeHealth{
		{Name: "us1", Qualified: true, Alive: true},
		{Name: "us2", Qualified: true, Alive: true},
		{Name: "us3", Qualified: true, Alive: true},
	}
	got := s.computePoolMembers(nodes, nil, 0)["ai-pool"]
	if len(got) != 2 || got[0] != "us2" || got[1] != "us3" {
		t.Fatalf("sticky members = %v, want [us2 us3] (us1 cannot beat the 400 margin)", got)
	}

	// Margin zero: the best challenger replaces the worst incumbent.
	s.cfg.SwapThresholdScore = 0
	got = s.computePoolMembers(nodes, nil, 0)["ai-pool"]
	if len(got) != 2 || got[0] != "us1" || got[1] != "us2" {
		t.Fatalf("members after margin=0 = %v, want [us1 us2]", got)
	}
}

// TestFilterCandidates_MultiPattern checks the union discovery used to find
// class-pool nodes outside the global pattern's region.
func TestFilterCandidates_MultiPattern(t *testing.T) {
	outbounds := []subscribe.Outbound{
		{"tag": "hutao/美国_A"},
		{"tag": "hutao/日本_A"},
		{"tag": "momo/🇸🇬新加坡1"},
	}
	proxies := map[string]map[string]interface{}{
		"hutao/美国_A":  {},
		"hutao/日本_A":  {},
		"momo/🇸🇬新加坡1": {},
	}
	got := filterCandidates(outbounds, []string{`美国`, `日本`}, proxies)
	if len(got) != 2 || got[0] != "hutao/美国_A" || got[1] != "hutao/日本_A" {
		t.Fatalf("filterCandidates = %v, want [hutao/美国_A hutao/日本_A]", got)
	}
}

// TestInTrialConfigurable pins the trial_duration knob: a deliberate
// region migration needs a shorter trial than the 24h default, while zero
// must keep the historical behavior.
func TestInTrialConfigurable(t *testing.T) {
	s := newTestScorer(defaultCfg())
	now := time.Now()
	s.ewma = map[string]*nodeEWMA{
		"n": {FirstSeenAt: now.Add(-10 * time.Minute)},
	}
	s.cfg.TrialDuration = 15 * time.Minute
	if !s.inTrial("n", now) {
		t.Error("10m-old node must be in a 15m trial")
	}
	s.cfg.TrialDuration = 5 * time.Minute
	if s.inTrial("n", now) {
		t.Error("10m-old node must be past a 5m trial")
	}
	// Zero falls back to the 24h constant.
	s.cfg.TrialDuration = 0
	if !s.inTrial("n", now) {
		t.Error("zero TrialDuration must fall back to the 24h default")
	}
}

func TestPoolMembersEqual(t *testing.T) {
	a := map[string][]string{"p": {"x", "y"}}
	if !poolMembersEqual(a, map[string][]string{"p": {"y", "x"}}) {
		t.Error("order-insensitive equal should be true")
	}
	if poolMembersEqual(a, map[string][]string{"p": {"x"}}) {
		t.Error("different size should be unequal")
	}
	if poolMembersEqual(a, map[string][]string{"q": {"x", "y"}}) {
		t.Error("different key should be unequal")
	}
}

// TestPassiveStats verifies close-event classification: a connection that
// closed having moved < minHandshakeBytes counts as failed; one that moved
// real data does not. FailRate = failed/closed.
func TestPassiveStats(t *testing.T) {
	s := newTestScorer(defaultCfg())
	s.activeConns = map[string]int{"nodeA": 3}
	now := time.Now()
	s.closeEvents = map[string][]closeEvent{
		"nodeA": {
			{at: now, failed: true},  // RST before handshake
			{at: now, failed: true},  // ditto
			{at: now, failed: false}, // real transfer
			{at: now, failed: false},
		},
	}
	ps := s.passiveStatsLocked("nodeA")
	if ps == nil {
		t.Fatal("expected stats for nodeA")
	}
	if ps.ActiveConns != 3 || ps.ClosedWindow != 4 || ps.FailedWindow != 2 {
		t.Errorf("got active=%d closed=%d failed=%d, want 3/4/2",
			ps.ActiveConns, ps.ClosedWindow, ps.FailedWindow)
	}
	if ps.FailRate != 0.5 {
		t.Errorf("fail_rate = %v, want 0.5", ps.FailRate)
	}
	// A node with nothing observed → nil (absent JSON field).
	if s.passiveStatsLocked("ghost") != nil {
		t.Error("unobserved node should yield nil passive stats")
	}
}

func TestScoreNode_AllGood(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	pData := buildProxyEntry(true, "http://test", []int{150, 155, 148, 162, 151, 153, 149, 157})
	h := s.scoreNode("ctc/US-01", pData, 0)
	if !h.Alive {
		t.Error("expected alive=true")
	}
	if !h.Qualified {
		t.Errorf("expected qualified, got reason=%q", h.Reason)
	}
	if h.RTTP50Ms <= 0 {
		t.Errorf("p50 not computed: %d", h.RTTP50Ms)
	}
	if h.RTTP95Ms < h.RTTP50Ms {
		t.Errorf("p95 < p50: %d < %d", h.RTTP95Ms, h.RTTP50Ms)
	}
}

func TestScoreNode_HighFailRateStillQualified(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	// 3 of 8 probes failed = 0.375. Under the post-Plan-A policy this no
	// longer disqualifies (mihomo's 30s health-check is the fast gate;
	// scorer only filters chronic / window-wide failure). FailRate is
	// still computed and exposed for /api/nodes/health observability.
	pData := buildProxyEntry(true, "http://test", []int{0, 150, 0, 155, 0, 148, 162, 151})
	h := s.scoreNode("ash/US-01", pData, 0)
	if !h.Qualified {
		t.Errorf("expected qualified (fail_rate is observability-only now), reason=%q", h.Reason)
	}
	if h.FailRate <= 0 {
		t.Errorf("fail_rate not computed: %f", h.FailRate)
	}
}

func TestScoreNode_RTTP95SpikeStillQualified(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	// One massive spike makes p95 > 800ms. No longer disqualifying — a
	// flapping airport node is mihomo's problem, not the scorer's.
	pData := buildProxyEntry(true, "http://test", []int{200, 210, 190, 205, 195, 215, 200, 2000})
	h := s.scoreNode("yuyun/US-01", pData, 0)
	if !h.Qualified {
		t.Errorf("expected qualified (rtt_p95 is observability-only now), reason=%q", h.Reason)
	}
	if h.RTTP95Ms <= 800 {
		t.Errorf("p95 should have been computed > 800, got %d", h.RTTP95Ms)
	}
}

func TestScoreNode_HighJitterStillQualified(t *testing.T) {
	t.Parallel()
	cfg := defaultCfg()
	cfg.MaxJitterMs = 80
	s := newTestScorer(cfg)
	// p50≈160ms but occasional 700ms → jitter > 80ms. Observability-only.
	pData := buildProxyEntry(true, "http://test", []int{155, 160, 158, 162, 155, 165, 700, 720})
	h := s.scoreNode("nideming/US-01", pData, 0)
	if !h.Qualified {
		t.Errorf("expected qualified (jitter is observability-only now), reason=%q", h.Reason)
	}
	if h.JitterMs <= 0 {
		t.Errorf("jitter not computed: %d", h.JitterMs)
	}
}

func TestScoreNode_NoRecentSuccessDisqualified(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	// Last 5 of 8 are all zero → window-wide failure → disqualified.
	// (First 3 succeeded — irrelevant since they fall outside the window.)
	pData := buildProxyEntry(true, "http://test", []int{200, 210, 190, 0, 0, 0, 0, 0})
	h := s.scoreNode("ash/US-01", pData, 0)
	if h.Qualified {
		t.Error("expected disqualified — last 5 probes all failed")
	}
	if h.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestScoreNode_DeadNode(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	pData := buildProxyEntry(false, "http://test", []int{})
	h := s.scoreNode("nideming/dead", pData, 0)
	if h.Qualified {
		t.Error("dead node must not qualify")
	}
	if h.Reason == "" {
		t.Error("expected non-empty reason for dead node")
	}
}

func TestScoreNode_NotEnoughProbes(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	// Only 1 probe when MinProbes=2 → benefit of doubt (don't evict new nodes)
	pData := buildProxyEntry(true, "http://test", []int{9999})
	h := s.scoreNode("new/US-01", pData, 0)
	if !h.Qualified {
		t.Error("node with insufficient probe history should get benefit of doubt")
	}
}

func TestScoreNode_ThroughputPassThrough(t *testing.T) {
	t.Parallel()
	s := newTestScorer(defaultCfg())
	pData := buildProxyEntry(true, "http://test", []int{150, 155, 148, 162, 151, 153, 149, 157})
	h := s.scoreNode("ctc/US-01", pData, 12345.6)
	if h.ThroughputBps != 12345.6 {
		t.Errorf("throughput not preserved: %v", h.ThroughputBps)
	}
}

func TestPoolSetsEqual(t *testing.T) {
	a := map[string]bool{"x": true, "y": true}
	b := map[string]bool{"x": true, "y": true}
	c := map[string]bool{"x": true}
	if !poolSetsEqual(a, b) {
		t.Error("equal sets should be equal")
	}
	if poolSetsEqual(a, c) {
		t.Error("different sets should not be equal")
	}
}

func TestPercentile(t *testing.T) {
	vals := []int{100, 200, 300, 400, 500}
	if p50 := percentile(vals, 50); p50 != 300 {
		t.Errorf("p50 = %d, want 300", p50)
	}
	if p95 := percentile(vals, 95); p95 < 480 {
		t.Errorf("p95 = %d, want ≥480", p95)
	}
	if p0 := percentile(vals, 0); p0 != 100 {
		t.Errorf("p0 = %d, want 100", p0)
	}
	if p100 := percentile(vals, 100); p100 != 500 {
		t.Errorf("p100 = %d, want 500", p100)
	}
}
