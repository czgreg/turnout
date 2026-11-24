package subscribe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// modeServer answers each request according to the current mode and counts
// requests. "ok" serves body, "429" rate-limits, "empty" serves a
// subscription with no nodes, "slow" stalls past the client timeout.
type modeServer struct {
	mu    sync.Mutex
	mode  []string // consumed one per request; the last one repeats
	body  string
	hits  int
	srv   *httptest.Server
	token string
}

func newModeServer(body string, modes ...string) *modeServer {
	s := &modeServer{mode: modes, body: body, token: "/s/v2/SECRETTOKEN123"}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.hits++
		m := s.mode[0]
		if len(s.mode) > 1 {
			s.mode = s.mode[1:]
		}
		s.mu.Unlock()
		switch m {
		case "ok":
			_, _ = w.Write([]byte(s.body))
		case "429":
			http.Error(w, "slow down", http.StatusTooManyRequests)
		case "empty":
			_, _ = w.Write([]byte("proxies: []\n"))
		case "slow":
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		}
	}))
	return s
}

func (s *modeServer) url() string { return s.srv.URL + s.token }

func (s *modeServer) set(modes ...string) {
	s.mu.Lock()
	s.mode, s.hits = modes, 0
	s.mu.Unlock()
}

func (s *modeServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func healthOf(t *testing.T, m *Manager, name string) SubscriptionHealth {
	t.Helper()
	for _, h := range m.LastHealth() {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("no health for %s", name)
	return SubscriptionHealth{}
}

// TestRefresh_FetchErrorKeepsLastGood is the hutao shape on 6.15
// (2026-10-24): a 429 used to drop every hutao node from the render until
// someone refreshed again, and refresh_interval: 0s means nobody does.
func TestRefresh_FetchErrorKeepsLastGood(t *testing.T) {
	s := newModeServer(clashBody(3, 0), "ok")
	defer s.srv.Close()
	m := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "hutao", URL: s.url(), Format: "auto", Enabled: true},
	}, 2*time.Second, DefaultUserAgent)

	if res, _ := m.Refresh(context.Background()); len(res) != 1 || len(res[0].Outbounds) != 3 {
		t.Fatalf("round 1: want 3 nodes, got %+v", res)
	}

	for round := 2; round <= 3; round++ {
		s.set("429")
		res, err := m.Refresh(context.Background())
		if err == nil {
			t.Errorf("round %d: Refresh must still report the fetch error", round)
		}
		if len(res) != 1 || len(res[0].Outbounds) != 3 {
			t.Fatalf("round %d: want the 3 last-good nodes carried over, got %+v", round, res)
		}
		if got := len(m.AllOutbounds()); got != 3 {
			t.Errorf("round %d: AllOutbounds = %d, want 3", round, got)
		}
		h := healthOf(t, m, "hutao")
		if h.Outcome != "fetch_error" || h.StaleNodes != 3 {
			t.Errorf("round %d: health = %s stale=%d, want fetch_error stale=3", round, h.Outcome, h.StaleNodes)
		}
		if strings.Contains(h.Err, "SECRETTOKEN") {
			t.Errorf("round %d: health err leaks the token: %s", round, h.Err)
		}
		if s.count() != 1 {
			t.Errorf("round %d: a 429 must not be retried, got %d requests", round, s.count())
		}
	}
}

// An upstream that answers with zero nodes has answered: no fallback.
func TestRefresh_ZeroNodesDoesNotFallBack(t *testing.T) {
	s := newModeServer(clashBody(3, 0), "ok")
	defer s.srv.Close()
	m := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "p", URL: s.url(), Format: "auto", Enabled: true},
	}, 2*time.Second, DefaultUserAgent)
	_, _ = m.Refresh(context.Background())

	s.set("empty")
	if res, _ := m.Refresh(context.Background()); len(res) != 1 || len(res[0].Outbounds) != 0 {
		t.Fatalf("zero-node answer must win, got %+v", res)
	}
	// ...and it also clears lastGood, so a later fetch error has nothing to
	// carry over.
	s.set("429")
	res, _ := m.Refresh(context.Background())
	if len(res) != 0 || healthOf(t, m, "p").StaleNodes != 0 {
		t.Errorf("after a zero-node round, a fetch error must not resurrect older nodes: %+v", res)
	}
}

// Re-pointing a subscription must never resurrect the old URL's nodes.
func TestRefresh_URLChangeDropsLastGood(t *testing.T) {
	s := newModeServer(clashBody(3, 0), "ok")
	defer s.srv.Close()
	m := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "p", URL: s.url(), Format: "auto", Enabled: true},
	}, 2*time.Second, DefaultUserAgent)
	_, _ = m.Refresh(context.Background())

	s.set("429")
	m.SetEntries([]config.SubscriptionEntry{
		{Name: "p", URL: s.srv.URL + "/s/v2/OTHER", Format: "auto", Enabled: true},
	})
	res, _ := m.Refresh(context.Background())
	if len(res) != 0 || healthOf(t, m, "p").StaleNodes != 0 {
		t.Errorf("new URL failing must not carry the old URL's nodes: %+v", res)
	}
}

// A timed-out fetch is retried once; a second timeout falls back.
func TestRefresh_TimeoutRetriedOnce(t *testing.T) {
	s := newModeServer(clashBody(2, 0), "slow", "ok")
	defer s.srv.Close()
	m := NewManagerWithFetch([]config.SubscriptionEntry{
		{Name: "p", URL: s.url(), Format: "auto", Enabled: true, UserAgent: DefaultUserAgent},
	}, 200*time.Millisecond, DefaultUserAgent)

	res, err := m.Refresh(context.Background())
	if err != nil || len(res) != 1 || len(res[0].Outbounds) != 2 {
		t.Fatalf("timeout then ok: want 2 nodes and no error, got %+v err=%v", res, err)
	}
	// The explicit-UA advisory probes alternatives after a success, so count
	// only up to the success: 1 timeout + 1 retry.
	if h := healthOf(t, m, "p"); h.Outcome != "ok" {
		t.Errorf("outcome = %s, want ok", h.Outcome)
	}

	s.set("slow")
	res, _ = m.Refresh(context.Background())
	if got := s.count(); got != 2 {
		t.Errorf("two timeouts: want exactly 1 retry (2 requests), got %d", got)
	}
	h := healthOf(t, m, "p")
	if h.Outcome != "fetch_error" || h.StaleNodes != 2 || len(res) != 1 {
		t.Errorf("after two timeouts: want fetch_error with 2 stale nodes, got %s stale=%d res=%d", h.Outcome, h.StaleNodes, len(res))
	}
	if strings.Contains(h.Err, "SECRETTOKEN") {
		t.Errorf("timeout error leaks the token: %s", h.Err)
	}
}
