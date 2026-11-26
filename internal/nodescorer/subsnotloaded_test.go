// The scorer must not render before the first subscription refresh has
// landed. After every turnout-gateway restart in production (2026-11-26
// 11:40, 11:47, 13:37, 13:39) the 10s-warm-up round ran while the refresh
// was still probing UAs (~20-23s), so AllOutbounds() was empty. mihomo itself
// was not restarted and still answered /proxies, so the round scored fine and
// hot-reloaded a config rendered from ZERO outbounds: no proxies, no
// default-pool, no dns-out, ai-pool as a DIRECT stub. For ~12s until the
// refresh re-rendered, AI traffic went direct, MATCH traffic went DIRECT, and
// every dns-out DoH dial failed (dnspreload "ok=0 fail=15").

package nodescorer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

func TestScore_SkipsRoundUntilSubscriptionsLoaded(t *testing.T) {
	const probeURL = "http://probe.test/generate_204"
	nodes := map[string]proxyNode{
		"sub/US-A": {alive: true, history: goodHistory(100)},
		"sub/US-B": {alive: true, history: goodHistory(120)},
		"sub/HK-A": {alive: true, history: goodHistory(80)},
	}
	apiAddr, _ := mockClashAPI(t, probeURL, nodes)
	fr := &fakeRenderer{path: t.TempDir() + "/config.yaml"}

	var mu sync.Mutex
	var feed []subscribe.Outbound // empty: first refresh still in flight
	s := New(kGatingCfg(3), []config.PoolConfig{{Name: "ai-pool", NodePattern: "US", Size: 2}},
		apiAddr, "", probeURL, "", fr, func() []subscribe.Outbound {
			mu.Lock()
			defer mu.Unlock()
			return feed
		})
	t.Cleanup(func() { time.Sleep(50 * time.Millisecond) })
	// Restored from nodescorer-state.json, as on every production restart.
	s.poolSet = map[string]bool{"sub/US-A": true, "sub/HK-A": true}

	if s.score(context.Background()) {
		t.Fatal("score reported success before any subscription outbound was loaded")
	}
	time.Sleep(100 * time.Millisecond)
	if _, _, renders := fr.snapshot(); renders != 0 {
		t.Fatalf("rendered %d config(s) from zero outbounds — mihomo would lose every proxy", renders)
	}
	if len(s.poolSet) != 2 || !s.poolSet["sub/US-A"] || !s.poolSet["sub/HK-A"] {
		t.Errorf("skipped round mutated the restored poolSet: %v", s.poolSet)
	}

	// The refresh lands; the startup retry's next attempt proceeds.
	mu.Lock()
	for tag := range nodes {
		feed = append(feed, outbound(tag))
	}
	mu.Unlock()
	if !s.score(context.Background()) {
		t.Fatal("score failed once subscriptions were loaded")
	}
	fr.waitRenders(t, 1)
	if got := s.poolMembers["ai-pool"]; len(got) == 0 {
		t.Errorf("ai-pool has no members after the first complete round")
	}
}

// Belt-and-braces at the render itself: whatever the caller, a config built
// from no outbounds is never published, and the render trigger is re-armed so
// the next round retries.
func TestHotReload_RefusesEmptyOutbounds(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	fr := &fakeRenderer{path: t.TempDir() + "/config.yaml"}
	s := New(defaultCfg(), nil, strings.TrimPrefix(srv.URL, "http://"), "", testProbeURL, "", fr,
		func() []subscribe.Outbound { return nil })
	s.lastDefaultPoolRendered = map[string]bool{"sub/a": true}

	s.hotReload(context.Background(), []string{"sub/a"}, []string{"sub/a"},
		map[string][]string{"ai-pool": {"sub/a"}}, nil)

	if _, _, renders := fr.snapshot(); renders != 0 {
		t.Fatalf("renderer called %d time(s) with zero outbounds", renders)
	}
	if s.lastDefaultPoolRendered != nil {
		t.Fatal("refused render must clear lastDefaultPoolRendered so the next round retries")
	}
}
