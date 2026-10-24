package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLastReloadDuration(t *testing.T) {
	cases := []struct {
		name string
		text string
		want int
	}{
		{"ms", `msg="nodescorer: pool updated + hot-reloaded" duration=573ms`, 573},
		{"seconds", `duration=6.303s`, 6303},
		{"micro", `duration=120µs`, 0},
		{"last wins", "duration=100ms\nduration=250ms", 250},
		{"none", "no reload here", 0},
	}
	for _, c := range cases {
		if got := lastReloadDuration(c.text); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCountLogSignals(t *testing.T) {
	text := "level=INFO msg=ok\nlevel=WARN msg=slow\nlevel=warning msg=x\n" +
		`nodescorer: pool updated + hot-reloaded` + "\n" + `hot-reload failed`
	if got := countLogSignals(text, "level=warn"); got != 2 {
		t.Errorf("warn count = %d, want 2", got)
	}
	if got := countLogSignals(text, "hot-reloaded"); got != 1 {
		t.Errorf("reload count = %d, want 1", got)
	}
	if got := countLogSignals(text, "hot-reload failed"); got != 1 {
		t.Errorf("fail count = %d, want 1", got)
	}
}

func TestScanConfigCounts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "proxy-groups:\n" +
		"  - name: fb-p-abc\n    type: fallback\n" +
		"  - name: fb-p-def\n    type: fallback\n" +
		"sub-rules:\n  perterm:\n" +
		"    - SRC-IP-SUFFIX,0.0.0.0/10,fb-p-abc\n" +
		"    - SRC-IP-SUFFIX,0.0.0.1/10,fb-p-def\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, size, fallbacks, rules, err := scanConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(body)) {
		t.Errorf("size = %d, want %d", size, len(body))
	}
	if fallbacks != 2 {
		t.Errorf("fallback groups = %d, want 2", fallbacks)
	}
	if rules != 2 {
		t.Errorf("perterm rules = %d, want 2", rules)
	}
}

func TestPct(t *testing.T) {
	if got := pct(nil, 0.5); got != 0 {
		t.Errorf("empty pct = %d", got)
	}
	v := []int{50, 10, 30, 20, 40}
	if got := pct(v, 0.5); got != 30 {
		t.Errorf("p50 = %d, want 30", got)
	}
	if got := pct(v, 0.95); got != 50 {
		t.Errorf("p95 = %d, want 50", got)
	}
	// pct must not mutate the caller's slice order.
	if v[0] != 50 {
		t.Errorf("pct mutated input: %v", v)
	}
}

func TestSummaryAdd(t *testing.T) {
	now := time.Now().Format(time.RFC3339)
	var s summary
	s.add(Sample{
		TS:      now,
		Health:  HealthPart{OK: true},
		Churn:   &ChurnPart{Interval: 2},
		Reload:  ReloadPart{FallbackGroups: 68},
		Journal: JournalPart{HotReloads: 1, LastDurationMs: 600, GatewayWarns: 1},
		DNS:     &DNSPart{Domain: "a", OK: true, Ms: 100},
		Direct:  map[string]int{"1.1.1.1:853": -1},
		Proxy:   &ProxyPart{OK: true, Ms: 300},
		Res:     ResPart{MihomoRSSMB: 100},
	})
	s.add(Sample{
		TS:      now,
		Health:  HealthPart{OK: false},
		Churn:   &ChurnPart{Interval: 1},
		Reload:  ReloadPart{FallbackGroups: 68},
		Journal: JournalPart{HotReloads: 1, LastDurationMs: 800, GatewayWarns: 1},
		DNS:     &DNSPart{Domain: "b", OK: false, Ms: 5000},
		Direct:  map[string]int{"1.1.1.1:853": 30},
		Proxy:   &ProxyPart{OK: false},
		Res:     ResPart{MihomoRSSMB: 110},
	})
	if s.samples != 2 || s.hotReloads != 2 || s.transitions != 3 {
		t.Errorf("counters: samples=%d reloads=%d transitions=%d", s.samples, s.hotReloads, s.transitions)
	}
	if s.reloadDurMax != 800 || s.reloadDurSum != 1400 {
		t.Errorf("durations: max=%d sum=%d", s.reloadDurMax, s.reloadDurSum)
	}
	if s.dnsOK != 1 || s.dnsTotal != 2 {
		t.Errorf("dns: ok=%d total=%d", s.dnsOK, s.dnsTotal)
	}
	if s.directFails["1.1.1.1:853"] != 1 || s.directTotal["1.1.1.1:853"] != 2 {
		t.Errorf("direct: fails=%d total=%d", s.directFails["1.1.1.1:853"], s.directTotal["1.1.1.1:853"])
	}
	if s.proxyOK != 1 || s.proxyTotal != 2 {
		t.Errorf("proxy: ok=%d total=%d", s.proxyOK, s.proxyTotal)
	}
	if s.fallbackMin != 68 || s.fallbackMax != 68 {
		t.Errorf("fallback: min=%d max=%d", s.fallbackMin, s.fallbackMax)
	}
	if s.healthBad != 1 {
		t.Errorf("healthBad = %d, want 1", s.healthBad)
	}
}
