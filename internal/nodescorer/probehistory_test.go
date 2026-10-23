package nodescorer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

// The shapes below are from 10.100.6.15 on 2026-10-23: every PUT /configs
// makes mihomo (re)create ~2k proxy groups, and a routing member sits in
// 250-500 of them, so the node is dialled hundreds of times in the same
// instant and every result is appended to one shared history window.
const testProbeURL = "http://probe.test/generate_204"

func ts(base time.Time, d time.Duration) string {
	return base.Add(d).Format(time.RFC3339Nano)
}

func burstHistory(t *testing.T, entries []struct {
	offset time.Duration
	delay  int
}) []interface{} {
	t.Helper()
	base := time.Date(2026, 10, 23, 18, 54, 55, 0, time.UTC)
	out := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		out = append(out, map[string]interface{}{
			"time":  ts(base, e.offset),
			"delay": float64(e.delay),
		})
	}
	return out
}

func proxyEntryWithHistory(alive bool, history []interface{}) map[string]interface{} {
	return map[string]interface{}{
		"alive": alive,
		"extra": map[string]interface{}{
			testProbeURL: map[string]interface{}{"alive": alive, "history": history},
		},
	}
}

// A reload burst is ONE observation, not eight. mihomo recorded 8 results
// within 3ms (6 timeouts, 2 five-second stragglers); the probes that followed
// at the normal cadence were 56-60ms. Counting the burst term by term is what
// made a 56ms node read fail_rate 0.5 and get cycled out of the pool.
func TestScoreNode_ReloadBurstIsOneObservation(t *testing.T) {
	s := newTestScorer(defaultCfg())
	hist := burstHistory(t, []struct {
		offset time.Duration
		delay  int
	}{
		{0, 0}, {1 * time.Millisecond, 5331}, {2 * time.Millisecond, 0},
		{30 * time.Millisecond, 0}, {100 * time.Millisecond, 0},
		{2 * time.Second, 0}, {3 * time.Second, 5430},
		{19 * time.Second, 60}, {107 * time.Second, 58}, {195 * time.Second, 56},
	})

	h := s.scoreNode("sub/hk01", proxyEntryWithHistory(true, hist), 0)

	if h.FailRate != 0 {
		t.Fatalf("fail_rate = %.2f, want 0: the burst is one observation and the last probe in that window succeeded", h.FailRate)
	}
	if h.RTTP95Ms > 100 {
		t.Fatalf("p95 = %d, want ~60: burst timeouts must not set the latency tail", h.RTTP95Ms)
	}
	if h.ProbeCount != 3 {
		t.Fatalf("probe_count = %d, want 3 independent observations", h.ProbeCount)
	}
	if !h.Qualified {
		t.Fatalf("expected qualified, got reason=%q", h.Reason)
	}
}

// A burst that is still failing when the window ends is still a failure.
// Collapsing must not turn "dead node probed ten times in one second" into
// a clean sample.
func TestScoreNode_AllFailedBurstStaysAFailure(t *testing.T) {
	s := newTestScorer(defaultCfg())
	base := time.Date(2026, 10, 23, 18, 54, 55, 0, time.UTC)
	hist := make([]interface{}, 0, 10)
	for i := 0; i < 10; i++ {
		hist = append(hist, map[string]interface{}{
			"time":  ts(base, time.Duration(i)*time.Millisecond),
			"delay": float64(0),
		})
	}

	h := s.scoreNode("sub/dead", proxyEntryWithHistory(false, hist), 0)

	if h.ProbeCount != 1 {
		t.Fatalf("probe_count = %d, want 1 (one burst)", h.ProbeCount)
	}
	if h.FailRate != 1 {
		t.Fatalf("fail_rate = %.2f, want 1", h.FailRate)
	}
	if h.Qualified {
		t.Fatal("a node whose only observation failed must not be qualified")
	}
}

func TestSampleProbes_SteadyStateUntouched(t *testing.T) {
	base := time.Date(2026, 10, 23, 18, 0, 0, 0, time.UTC)
	samples := make([]probeSample, 10)
	for i := range samples {
		samples[i] = probeSample{Delay: 50 + i, At: base.Add(time.Duration(i) * 30 * time.Second)}
	}
	got := sampleProbes(samples)
	if len(got) != 10 {
		t.Fatalf("kept %d samples, want 10: a 30s cadence is never merged", len(got))
	}
	for i := range got {
		if got[i] != 50+i {
			t.Fatalf("sample %d = %d, want %d (oldest→newest order preserved)", i, got[i], 50+i)
		}
	}
}

// Timestamps that cannot be parsed fall back to the raw history: guessing an
// ordering would be worse than the pre-sampling behaviour.
func TestSampleProbes_MissingTimestampsFallBackToRaw(t *testing.T) {
	samples := []probeSample{{Delay: 0}, {Delay: 0}, {Delay: 120}}
	if got := sampleProbes(samples); len(got) != 3 || got[2] != 120 {
		t.Fatalf("got %v, want the raw [0 0 120]", got)
	}
}

func TestSampleProbes_Empty(t *testing.T) {
	if got := sampleProbes(nil); len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// A reload that never reached mihomo must re-arm the render trigger, or the
// next round compares against an intent that was never applied and the pool
// silently diverges from the data plane.
func TestHotReload_FailureRearmsRender(t *testing.T) {
	var status int32
	status = http.StatusInternalServerError
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(atomic.LoadInt32(&status)))
	}))
	defer srv.Close()

	fr := &fakeRenderer{path: t.TempDir() + "/config.yaml"}
	s := New(defaultCfg(), nil, strings.TrimPrefix(srv.URL, "http://"), "", testProbeURL, "", fr,
		func() []subscribe.Outbound { return nil })

	s.lastDefaultPoolRendered = map[string]bool{"sub/a": true}
	s.hotReload(context.Background(), []string{"sub/a"}, []string{"sub/a"}, nil)
	if s.lastDefaultPoolRendered != nil {
		t.Fatal("failed reload must clear lastDefaultPoolRendered so the next round retries")
	}

	atomic.StoreInt32(&status, http.StatusNoContent)
	s.lastDefaultPoolRendered = map[string]bool{"sub/a": true}
	s.hotReload(context.Background(), []string{"sub/a"}, []string{"sub/a"}, nil)
	if s.lastDefaultPoolRendered == nil {
		t.Fatal("successful reload must leave lastDefaultPoolRendered alone (score() owns it)")
	}
}
