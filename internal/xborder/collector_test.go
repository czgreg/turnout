package xborder

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeMihomo serves /connections from a settable snapshot.
type fakeMihomo struct {
	mu    sync.Mutex
	conns []map[string]any
	fail  bool
}

func (f *fakeMihomo) set(conns ...map[string]any) {
	f.mu.Lock()
	f.conns = conns
	f.mu.Unlock()
}

func (f *fakeMihomo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/connections" {
		http.NotFound(w, r)
		return
	}
	if f.fail {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"connections": f.conns})
}

func conn(id, typ, src, sport, dport, host, sniff, dstIP string, up, down int64, start time.Time, chains ...string) map[string]any {
	return map[string]any{
		"id": id,
		"metadata": map[string]any{
			"network": "tcp", "type": typ, "sourceIP": src, "sourcePort": sport,
			"destinationIP": dstIP, "destinationPort": dport, "host": host, "sniffHost": sniff,
		},
		"upload": up, "download": down, "start": start.Format(time.RFC3339Nano),
		"chains": chains, "rule": "SubRules", "rulePayload": "(RULE-SET,geosite-x)",
	}
}

type harness struct {
	c     *Collector
	fake  *fakeMihomo
	now   time.Time
	out   []Record
	ssErr error
}

func newHarness(t *testing.T) *harness {
	h := &harness{fake: &fakeMihomo{}, now: time.Date(2026, 11, 24, 10, 0, 0, 0, time.Local)}
	srv := httptest.NewServer(h.fake)
	t.Cleanup(srv.Close)
	h.c = NewCollector(Options{
		APIAddr:      srv.Listener.Addr().String(),
		Hostname:     "gw-test",
		Pools:        []string{"ai-pool"},
		PollInterval: time.Second,
		Emit:         func(r Record) { h.out = append(h.out, r) },
		OrigDsts: func(context.Context) (map[string]string, error) {
			if h.ssErr != nil {
				return nil, h.ssErr
			}
			return map[string]string{"192.0.2.10:5000": "203.0.113.9"}, nil
		},
		Now: func() time.Time { return h.now },
	})
	return h
}

func (h *harness) tick(d time.Duration) {
	h.now = h.now.Add(d)
	h.c.poll(context.Background())
}

func TestTrackedConnectionCloseRecord(t *testing.T) {
	h := newHarness(t)
	start := h.now
	c := conn("id-1", "TProxy", "192.0.2.10", "5000", "443", "chat.example.com", "chat.example.com", "",
		100, 200, start, "sub-a/美国_BGP_D", "fb-ai-pool-p-1")
	h.fake.set(c)
	h.tick(time.Second)
	// The establish line arrives after the first sample saw the connection.
	l, _ := parseLogLine("[TCP] 192.0.2.10:5000 --> chat.example.com:443 match SubRules((RULE-SET,geosite-x)) using fb-ai-pool-p-1[sub-a/美国_BGP_D]")
	h.c.onLine(l, h.now)

	c["upload"], c["download"] = int64(4600), int64(3000)
	h.fake.set(c)
	h.tick(time.Second)
	h.fake.set()
	h.tick(time.Second)

	if len(h.out) != 1 {
		t.Fatalf("records = %d, want 1: %+v", len(h.out), h.out)
	}
	r := h.out[0]
	if r.Event != EventClose || r.Schema != Schema || r.Seq != 1 || r.Gateway.Hostname != "gw-test" {
		t.Errorf("header = %+v", r)
	}
	if r.Conn.ID != "id-1" || r.Conn.DurationMs != 2000 || r.Conn.End == "" {
		t.Errorf("conn = %+v (end is the last sample, 2s after start)", r.Conn)
	}
	if r.Src != (SrcFields{IP: "192.0.2.10", Port: 5000}) {
		t.Errorf("src = %+v", r.Src)
	}
	if r.Dst != (DstFields{Host: "chat.example.com", SniffHost: "chat.example.com", IP: "203.0.113.9", Port: 443}) {
		t.Errorf("dst = %+v (ip comes from ss when mihomo has none)", r.Dst)
	}
	if r.Route.Pool != "ai-pool" || r.Route.Group != "fb-ai-pool-p-1" || len(r.Route.Chains) != 2 {
		t.Errorf("route = %+v", r.Route)
	}
	if r.Egress != (EgressFields{Node: "sub-a/美国_BGP_D", Region: "US"}) {
		t.Errorf("egress = %+v", r.Egress)
	}
	if r.Traffic == nil || *r.Traffic != (TrafficFields{UpBytes: 4600, DownBytes: 3000}) {
		t.Errorf("traffic = %+v (last sample, not final)", r.Traffic)
	}
	if r.Collect != (CollectFields{Tracked: true, Logged: true}) || r.Result.Status != "ok" {
		t.Errorf("collect/result = %+v %+v", r.Collect, r.Result)
	}
}

func TestLogLineBeforeFirstSampleIsClaimed(t *testing.T) {
	h := newHarness(t)
	l, _ := parseLogLine("[TCP] 192.0.2.10:5000 --> a.example:443 match Match using fb-p-1[sub/n]")
	h.c.onLine(l, h.now)
	h.fake.set(conn("id-1", "TProxy", "192.0.2.10", "5000", "443", "a.example", "", "198.51.100.1", 1, 1, h.now, "sub/n", "fb-p-1"))
	for i := 0; i < 10; i++ { // well past the pending grace
		h.tick(time.Second)
	}
	if len(h.out) != 0 {
		t.Fatalf("claimed line must not also be emitted on its own: %+v", h.out)
	}
	h.fake.set()
	h.tick(time.Second)
	if len(h.out) != 1 || !h.out[0].Collect.Logged || h.out[0].Dst.IP != "198.51.100.1" {
		t.Fatalf("want one logged close using mihomo's destinationIP, got %+v", h.out)
	}
}

func TestShortConnectionFromLogOnly(t *testing.T) {
	h := newHarness(t)
	l, _ := parseLogLine("[TCP] 192.0.2.10:6000 --> 203.0.113.5:443 match GeoIP(us) using fb-p-1[sub/🇸🇬新加坡01]")
	h.c.onLine(l, h.now)
	h.tick(time.Second)
	if len(h.out) != 0 {
		t.Fatalf("emitted before grace: %+v", h.out)
	}
	h.tick(h.c.pendingGrace())
	if len(h.out) != 1 {
		t.Fatalf("records = %d, want 1", len(h.out))
	}
	r := h.out[0]
	if r.Collect != (CollectFields{Tracked: false, Logged: true}) {
		t.Errorf("collect = %+v", r.Collect)
	}
	if r.Dst.Host != "" || r.Dst.IP != "203.0.113.5" {
		t.Errorf("an IP-literal target belongs in dst.ip: %+v", r.Dst)
	}
	if r.Egress.Region != "SG" || r.Route.Pool != "default-pool" || r.Conn.End != "" || r.Traffic == nil || r.Traffic.BytesFinal {
		t.Errorf("record = %+v", r)
	}
}

func TestNonOverseasAndGatewayTrafficIgnored(t *testing.T) {
	h := newHarness(t)
	h.fake.set(
		conn("d", "TProxy", "192.0.2.10", "1", "443", "cn.example", "", "", 1, 1, h.now, "DIRECT"),
		conn("g", "TProxy", "192.0.2.10", "2", "443", "cn.example", "", "", 1, 1, h.now, "DIRECT", "out"),
		conn("r", "TProxy", "192.0.2.10", "3", "443", "ads.example", "", "", 1, 1, h.now, "REJECT"),
		conn("i", "Inner", "", "", "443", "", "", "", 1, 1, h.now, "sub/n", "fb-p-1"),
		conn("p", "HTTP", "127.0.0.1", "4", "443", "probe.example", "", "", 1, 1, h.now, "sub/n", "probe-out"),
	)
	h.tick(time.Second)
	for _, m := range []string{
		"[TCP] 192.0.2.10:1 --> cn.example:443 match Match using DIRECT",
		"[TCP] 192.0.2.10:3 --> ads.example:443 match RuleSet(ads) using REJECT",
		"[TCP] dial DIRECT (match Match/) 192.0.2.10:9 --> cn.example:443 error: timeout",
	} {
		l, ok := parseLogLine(m)
		if !ok {
			t.Fatalf("parse %q", m)
		}
		h.c.onLine(l, h.now)
	}
	h.fake.set()
	h.tick(h.c.pendingGrace() + time.Second)
	if len(h.out) != 0 {
		t.Fatalf("want no records, got %+v", h.out)
	}
}

func TestDialErrors(t *testing.T) {
	h := newHarness(t)
	// An empty named pool renders as a select stub on DIRECT; learn it from a sample.
	h.fake.set(conn("x", "TProxy", "192.0.2.10", "1", "443", "a.example", "", "", 1, 1, h.now, "DIRECT", "ai-pool"))
	h.tick(time.Second)

	for _, m := range []string{
		"[TCP] dial ai-pool (match SubRules/(RULE-SET,geosite-x)) 192.0.2.10:2 --> a.example:443 error: dial tcp 198.51.100.1:443: i/o timeout",
		"[TCP] dial fb-p-1 (match SubRules/(RULE-SET,geosite-y)) 192.0.2.10:3 --> b.example:5228 error: relay.example:14117 connect error: i/o timeout",
	} {
		l, _ := parseLogLine(m)
		h.c.onLine(l, h.now)
	}
	if len(h.out) != 1 {
		t.Fatalf("records = %d, want 1 (DIRECT-stub group skipped): %+v", len(h.out), h.out)
	}
	r := h.out[0]
	if r.Event != EventDialError || r.Traffic != nil || r.Result.Status != "dial_error" ||
		r.Result.Error != "relay.example:14117 connect error: i/o timeout" ||
		r.Route.Group != "fb-p-1" || r.Route.Pool != "default-pool" || r.Egress.Node != "" || r.Dst.Port != 5228 {
		t.Errorf("record = %+v", r)
	}
	b, _ := json.Marshal(r)
	var m map[string]any
	json.Unmarshal(b, &m)
	if _, ok := m["traffic"]; ok {
		t.Errorf("dial_error must not carry traffic: %s", b)
	}
}

func TestFailedSampleClosesNothing(t *testing.T) {
	h := newHarness(t)
	h.fake.set(conn("id-1", "TProxy", "192.0.2.10", "5000", "443", "a.example", "", "198.51.100.1", 1, 1, h.now, "sub/n", "fb-p-1"))
	h.tick(time.Second)
	h.fake.mu.Lock()
	h.fake.fail = true
	h.fake.mu.Unlock()
	l, _ := parseLogLine("[TCP] 192.0.2.10:7000 --> b.example:443 match Match using fb-p-1[sub/n]")
	h.c.onLine(l, h.now)
	for i := 0; i < 10; i++ {
		h.tick(time.Second)
	}
	if len(h.out) != 0 {
		t.Fatalf("a failing /connections must not close or expire anything: %+v", h.out)
	}
}

func TestSSFailureLeavesDstIPEmpty(t *testing.T) {
	h := newHarness(t)
	h.ssErr = errors.New("ss: not found")
	h.fake.set(conn("id-1", "TProxy", "192.0.2.10", "5000", "443", "a.example", "", "", 1, 1, h.now, "sub/n", "fb-p-1"))
	h.tick(time.Second)
	h.fake.set()
	h.tick(time.Second)
	if len(h.out) != 1 || h.out[0].Dst.IP != "" {
		t.Fatalf("got %+v", h.out)
	}
}

func TestSeqIncrements(t *testing.T) {
	h := newHarness(t)
	for _, m := range []string{
		"[TCP] dial fb-p-1 192.0.2.10:1 --> a.example:443 error: x",
		"[TCP] dial fb-p-1 192.0.2.10:2 --> a.example:443 error: x",
	} {
		l, _ := parseLogLine(m)
		h.c.onLine(l, h.now)
	}
	if len(h.out) != 2 || h.out[0].Seq != 1 || h.out[1].Seq != 2 {
		t.Fatalf("got %+v", h.out)
	}
}
