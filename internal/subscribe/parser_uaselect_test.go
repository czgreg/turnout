package subscribe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// clashBody builds a Clash YAML with nTrojan trojan and nHy2 hysteria2 nodes.
func clashBody(nTrojan, nHy2 int) string {
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < nTrojan; i++ {
		fmt.Fprintf(&b, "- {name: tj-%d, type: trojan, server: t%d.example.com, port: 443, password: x, sni: example.com}\n", i, i)
	}
	for i := 0; i < nHy2; i++ {
		fmt.Fprintf(&b, "- {name: 美国HY-%d, type: hysteria2, server: h%d.example.com, port: 443, password: x}\n", i, i)
	}
	return b.String()
}

// uaRouter serves bodies[ua] for an exact UA match (500 otherwise) and
// counts requests per UA. bodies can be swapped between rounds via set.
type uaRouter struct {
	mu     sync.Mutex
	bodies map[string]string
	hits   map[string]int
}

func newUARouter(bodies map[string]string) (*uaRouter, *httptest.Server) {
	r := &uaRouter{bodies: bodies, hits: map[string]int{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ua := req.Header.Get("User-Agent")
		r.mu.Lock()
		r.hits[ua]++
		body, ok := r.bodies[ua]
		r.mu.Unlock()
		if !ok {
			http.Error(w, "unknown ua", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	return r, srv
}

func (r *uaRouter) set(ua, body string) {
	r.mu.Lock()
	r.bodies[ua] = body
	r.mu.Unlock()
}

func (r *uaRouter) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, v := range r.hits {
		n += v
	}
	return n
}

func (r *uaRouter) hitsFor(ua string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[ua]
}

func (r *uaRouter) reset() {
	r.mu.Lock()
	r.hits = map[string]int{}
	r.mu.Unlock()
}

// fakeClock is a settable clock for the TTL logic.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestRefresh_PicksLeastDowngradedUA is the wodi shape (2026-11): the legacy
// CFW UA gets a non-empty list with every hysteria2 node stripped, a modern
// UA gets the full list. Nothing fails, so only a comparison catches it.
func TestRefresh_PicksLeastDowngradedUA(t *testing.T) {
	t.Parallel()
	_, srv := newUARouter(map[string]string{
		gatedUA:              clashBody(40, 0),
		DefaultUserAgent:     clashBody(40, 33),
		"clash-verge/v2.0.0": clashBody(40, 33),
	})
	defer srv.Close()

	var gotUA string
	mgr := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "wodi", URL: srv.URL, Format: "auto", Enabled: true},
	}, 5*time.Second, gatedUA).
		WithUADiscoveryCallback(func(_, ua string) { gotUA = ua })

	if _, err := mgr.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	h := mgr.LastHealth()[0]
	if h.NodeCount != 73 || h.TypeCounts["hysteria2"] != 33 {
		t.Fatalf("NodeCount=%d types=%v, want 73 with 33 hysteria2", h.NodeCount, h.TypeCounts)
	}
	// Tie between mihomo and clash-verge → chain order picks mihomo.
	if h.EffectiveUA != DefaultUserAgent || gotUA != DefaultUserAgent {
		t.Errorf("EffectiveUA=%q callback=%q, want %q", h.EffectiveUA, gotUA, DefaultUserAgent)
	}
	if h.NodeDrop {
		t.Error("first round must not report a drop")
	}
}

// TestRefresh_UACacheTTL: inside the TTL the cached winner is used alone;
// after it, all candidates are compared again and a provider that changed
// which UA it favours is followed.
func TestRefresh_UACacheTTL(t *testing.T) {
	t.Parallel()
	r, srv := newUARouter(map[string]string{
		gatedUA:          clashBody(5, 0),
		DefaultUserAgent: clashBody(5, 3),
	})
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "s", URL: srv.URL, Format: "auto", Enabled: true},
	}, 5*time.Second, gatedUA)
	mgr.now = clk.now

	_, _ = mgr.Refresh(context.Background())
	if ua := mgr.LastHealth()[0].EffectiveUA; ua != DefaultUserAgent {
		t.Fatalf("round 1 ua = %q", ua)
	}

	r.reset()
	clk.add(time.Hour)
	_, _ = mgr.Refresh(context.Background())
	if r.total() != 1 || r.hitsFor(DefaultUserAgent) != 1 {
		t.Errorf("cached round: %d requests, want exactly 1 on %s", r.total(), DefaultUserAgent)
	}

	// Provider now serves clash-verge the most; mihomo unchanged.
	r.set("clash-verge/v2.0.0", clashBody(5, 10))
	r.reset()
	clk.add(uaProbeTTL)
	_, _ = mgr.Refresh(context.Background())
	if h := mgr.LastHealth()[0]; h.EffectiveUA != "clash-verge/v2.0.0" || h.NodeCount != 15 {
		t.Errorf("after TTL: ua=%q nodes=%d, want clash-verge/v2.0.0 with 15", h.EffectiveUA, h.NodeCount)
	}
	if r.total() < 2 {
		t.Errorf("after TTL expected a full probe, got %d requests", r.total())
	}
}

// TestRefresh_DropTriggersReprobe: the cached UA is suddenly downgraded
// mid-TTL. The drop forces an immediate comparison that finds the UA still
// serving everything — no drop is reported because it self-healed.
func TestRefresh_DropTriggersReprobe(t *testing.T) {
	t.Parallel()
	r, srv := newUARouter(map[string]string{
		DefaultUserAgent:     clashBody(10, 10),
		"clash-verge/v2.0.0": clashBody(10, 10),
	})
	defer srv.Close()

	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	mgr := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "s", URL: srv.URL, Format: "auto", Enabled: true},
	}, 5*time.Second, DefaultUserAgent)
	mgr.now = clk.now
	_, _ = mgr.Refresh(context.Background())

	r.set(DefaultUserAgent, clashBody(10, 0)) // hy2 stripped for mihomo now
	clk.add(time.Minute)
	_, _ = mgr.Refresh(context.Background())
	h := mgr.LastHealth()[0]
	if h.EffectiveUA != "clash-verge/v2.0.0" || h.NodeCount != 20 {
		t.Errorf("ua=%q nodes=%d, want clash-verge/v2.0.0 with 20", h.EffectiveUA, h.NodeCount)
	}
	if h.NodeDrop {
		t.Error("NodeDrop reported although re-probing restored the count")
	}
}

// TestRefresh_DropReportedWhenNoUAHelps: every UA lost the hy2 nodes (the
// provider really removed them, or downgraded everyone). Reported as
// NodeDrop with the previous count, and only once: the next round compares
// against the new baseline.
func TestRefresh_DropReportedWhenNoUAHelps(t *testing.T) {
	t.Parallel()
	r, srv := newUARouter(map[string]string{
		DefaultUserAgent: clashBody(10, 10),
	})
	defer srv.Close()

	mgr := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "s", URL: srv.URL, Format: "auto", Enabled: true},
	}, 5*time.Second, DefaultUserAgent)
	_, _ = mgr.Refresh(context.Background())

	r.set(DefaultUserAgent, clashBody(10, 0))
	_, _ = mgr.Refresh(context.Background())
	h := mgr.LastHealth()[0]
	if !h.NodeDrop || h.PrevNodeCount != 20 || h.NodeCount != 10 {
		t.Errorf("NodeDrop=%v prev=%d nodes=%d, want true/20/10", h.NodeDrop, h.PrevNodeCount, h.NodeCount)
	}
	if h.Outcome != "ok" {
		t.Errorf("outcome = %q, a drop with nodes left is still ok", h.Outcome)
	}

	_, _ = mgr.Refresh(context.Background())
	if mgr.LastHealth()[0].NodeDrop {
		t.Error("drop re-reported on the next round; baseline should have moved")
	}
}

// TestRefresh_ExplicitUANoSuggestionWhenBest: an explicit UA that already
// gets the most nodes produces no advisory.
func TestRefresh_ExplicitUANoSuggestionWhenBest(t *testing.T) {
	t.Parallel()
	_, srv := newUARouter(map[string]string{
		gatedUA:          clashBody(5, 0),
		DefaultUserAgent: clashBody(5, 5),
	})
	defer srv.Close()

	mgr := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "s", URL: srv.URL, Format: "auto", Enabled: true, UserAgent: DefaultUserAgent},
	}, 5*time.Second, gatedUA)
	_, _ = mgr.Refresh(context.Background())
	h := mgr.LastHealth()[0]
	if h.SuggestedUA != "" || h.EffectiveUA != DefaultUserAgent || h.NodeCount != 10 {
		t.Errorf("suggested=%q ua=%q nodes=%d", h.SuggestedUA, h.EffectiveUA, h.NodeCount)
	}
}

// TestRefresh_ExplicitUAAdvisory: an explicit legacy UA that is being
// downgraded keeps being used, and the better UA is reported.
func TestRefresh_ExplicitUAAdvisory(t *testing.T) {
	t.Parallel()
	_, srv := newUARouter(map[string]string{
		gatedUA:          clashBody(40, 0),
		DefaultUserAgent: clashBody(40, 33),
	})
	defer srv.Close()

	mgr := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "wodi", URL: srv.URL, Format: "auto", Enabled: true, UserAgent: gatedUA},
	}, 5*time.Second, DefaultUserAgent)
	_, _ = mgr.Refresh(context.Background())
	h := mgr.LastHealth()[0]
	if h.EffectiveUA != gatedUA || h.NodeCount != 40 {
		t.Errorf("explicit UA switched: ua=%q nodes=%d", h.EffectiveUA, h.NodeCount)
	}
	if h.SuggestedUA != DefaultUserAgent || h.SuggestedNodeCount != 73 {
		t.Errorf("suggested=%q (%d), want %s (73)", h.SuggestedUA, h.SuggestedNodeCount, DefaultUserAgent)
	}
}
