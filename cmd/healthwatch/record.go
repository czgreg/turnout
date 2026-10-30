package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Sample is one JSONL record. Field groups are pointer/omitempty so a broken
// subsystem leaves a gap instead of a misleading zero.
type Sample struct {
	TS       string         `json:"ts"`
	Health   HealthPart     `json:"health"`
	Watchdog *Watchdog      `json:"watchdog,omitempty"`
	Pool     *PoolPart      `json:"pool,omitempty"`
	Churn    *ChurnPart     `json:"churn,omitempty"`
	Reload   ReloadPart     `json:"reload"`
	Nodes    []NodePart     `json:"nodes,omitempty"`
	Terminal *TermPart      `json:"terminal,omitempty"`
	DNS      *DNSPart       `json:"dns,omitempty"`
	Direct   map[string]int `json:"direct_dns"`
	Proxy    *ProxyPart     `json:"proxy,omitempty"`
	Journal  JournalPart    `json:"journal"`
	Res      ResPart        `json:"resources"`
	Errors   []string       `json:"errors,omitempty"`
}

type HealthPart struct {
	OK        bool     `json:"ok"`
	LatencyMs int      `json:"latency_ms"`
	Failing   []string `json:"failing,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	Err       string   `json:"err,omitempty"`
}

type Watchdog struct {
	Enabled bool     `json:"enabled"`
	State   string   `json:"state,omitempty"`
	Failing []string `json:"failing,omitempty"`
}

type PoolPart struct {
	Size          int    `json:"size"`
	KTarget       int    `json:"k_target"`
	KCurrent      int    `json:"k_current"`
	Tier1         int    `json:"tier1"`
	Eligible      int    `json:"eligible"`
	Total         int    `json:"total"`
	NodeCount     int    `json:"node_count"`
	SupplyLimited bool   `json:"supply_limited"`
	SizingMode    string `json:"sizing_mode,omitempty"`
	LastUpdate    string `json:"last_update,omitempty"`
	LastRefresh   string `json:"last_refresh,omitempty"`
}

type ChurnPart struct {
	Interval int      `json:"interval"` // transitions since the previous sample
	Last5m   int      `json:"last_5m"`
	Last24h  int      `json:"last_24h"`
	LastAt   string   `json:"last_at,omitempty"`
	Added    []string `json:"last_added,omitempty"`
	Removed  []string `json:"last_removed,omitempty"`
}

type ReloadPart struct {
	ConfigMtime    string `json:"config_mtime,omitempty"`
	ConfigBytes    int64  `json:"config_bytes,omitempty"`
	ConfigChanged  bool   `json:"config_changed"`
	FallbackGroups int    `json:"fallback_groups"`
	PerTermRules   int    `json:"perterm_rules"`
	HotReloads     int    `json:"hot_reloads"`
	HotReloadFails int    `json:"hot_reload_fails"`
	ScoredRounds   int    `json:"scored_rounds"`
	WarmupSkips    int    `json:"warmup_skips"`
	LastDurationMs int    `json:"last_duration_ms,omitempty"`
	// Change attribution from the most recent "nodescorer: scored" line.
	// pool_changed alone conflated routing swaps with named-pool churn, which
	// sent the 2026-10-25 analysis through journald instead of the records.
	RoutingChanged bool `json:"routing_changed,omitempty"`
	ProbingChanged bool `json:"probing_changed,omitempty"`
	NamedChanged   bool `json:"named_changed,omitempty"`
	NamedDeferred  bool `json:"named_deferred,omitempty"`
}

type NodePart struct {
	Name        string  `json:"name"`
	Alive       bool    `json:"alive"`
	RTTP50      int     `json:"rtt_p50_ms"`
	RTTP95      int     `json:"rtt_p95_ms"`
	Jitter      int     `json:"jitter_ms"`
	FailRate    float64 `json:"fail_rate"`
	ProbeCount  int     `json:"probe_count"`
	Strikes     int     `json:"strikes"`
	OKRounds    int     `json:"ok_rounds"`
	ActiveConns int     `json:"active_conns,omitempty"`
}

type TermPart struct {
	IP          string  `json:"ip"`
	Group       string  `json:"group,omitempty"`
	ActiveNode  string  `json:"active_node,omitempty"`
	Primary     string  `json:"primary,omitempty"`
	Secondary   string  `json:"secondary,omitempty"`
	PrimaryOK   bool    `json:"primary_alive"`
	SecondOK    bool    `json:"secondary_alive"`
	PrimaryP50  int     `json:"primary_p50_ms,omitempty"`
	PrimaryP95  int     `json:"primary_p95_ms,omitempty"`
	SecondP50   int     `json:"secondary_p50_ms,omitempty"`
	SecondP95   int     `json:"secondary_p95_ms,omitempty"`
	PrimaryFail float64 `json:"primary_fail_rate,omitempty"`
	SecondFail  float64 `json:"secondary_fail_rate,omitempty"`
	// Pools carries the class-pool assignments (e.g. ai-pool). They are the
	// user-visible path for ChatGPT/Claude traffic and the most sensitive to
	// named-pool churn, so they get the same detail as the default pair.
	Pools []PoolAssign `json:"pools,omitempty"`
}

// PoolAssign is one class pool's assignment for the probe terminal.
type PoolAssign struct {
	Pool       string `json:"pool"`
	Group      string `json:"group,omitempty"`
	ActiveNode string `json:"active_node,omitempty"`
	Primary    string `json:"primary,omitempty"`
	Secondary  string `json:"secondary,omitempty"`
	PrimaryOK  bool   `json:"primary_alive"`
	SecondOK   bool   `json:"secondary_alive"`
	PrimaryP50 int    `json:"primary_p50_ms,omitempty"`
	PrimaryP95 int    `json:"primary_p95_ms,omitempty"`
}

type DNSPart struct {
	Domain string `json:"domain"`
	OK     bool   `json:"ok"`
	Ms     int    `json:"ms"`
	Cached bool   `json:"cached,omitempty"`
	Err    string `json:"err,omitempty"`
}

type ProxyPart struct {
	Group string `json:"group"`
	URL   string `json:"url"`
	OK    bool   `json:"ok"`
	Ms    int    `json:"ms"`
	Err   string `json:"err,omitempty"`
}

type JournalPart struct {
	HotReloads     int `json:"hot_reloads"`
	HotReloadFails int `json:"hot_reload_fails"`
	ScoredRounds   int `json:"scored_rounds"`
	WarmupSkips    int `json:"warmup_skips"`
	GatewayWarns   int `json:"gateway_warns"`
	GatewayErrors  int `json:"gateway_errors"`
	MihomoWarns    int `json:"mihomo_warns"`
	MihomoErrors   int `json:"mihomo_errors"`
	DNSFailures    int `json:"dns_failures"`
	LastDurationMs int `json:"last_reload_duration_ms,omitempty"`
}

type ResPart struct {
	MihomoRSSMB  float64 `json:"mihomo_rss_mb"`
	GatewayRSSMB float64 `json:"gateway_rss_mb"`
	Load1        float64 `json:"load1"`
	MemAvailMB   int64   `json:"mem_available_mb"`
	DiskFreeMB   int64   `json:"disk_free_mb"`
}

// ---- API response shapes (only the fields the sampler reads) ----

type statusResp struct {
	EngineOK     bool   `json:"engine_ok"`
	NodeCount    int    `json:"node_count"`
	PoolSize     int    `json:"pool_size"`
	PoolEligible int    `json:"pool_eligible"`
	PoolTotal    int    `json:"pool_total"`
	PoolLast     string `json:"pool_last_update"`
	LastRefresh  string `json:"last_refresh"`
	SizingMode   string `json:"sizing_mode"`
	PoolSizing   struct {
		KTarget       int  `json:"k_target"`
		KCurrent      int  `json:"k_current"`
		Tier1Count    int  `json:"tier1_count"`
		SupplyLimited bool `json:"supply_limited"`
	} `json:"pool_sizing"`
}

type healthResp struct {
	OK     bool   `json:"ok"`
	Scope  string `json:"scope,omitempty"`
	Detail string `json:"detail,omitempty"`
	Checks []struct {
		Name string `json:"name"`
		OK   bool   `json:"ok"`
	} `json:"checks"`
}

type watchdogResp struct {
	Enabled bool     `json:"enabled"`
	State   string   `json:"state"`
	Failing []string `json:"failing"`
	Detail  string   `json:"detail"`
}

type nodesResp struct {
	Nodes []struct {
		Name       string  `json:"name"`
		Alive      bool    `json:"alive"`
		RTTP50     int     `json:"rtt_p50_ms"`
		RTTP95     int     `json:"rtt_p95_ms"`
		Jitter     int     `json:"jitter_ms"`
		FailRate   float64 `json:"fail_rate"`
		ProbeCount int     `json:"probe_count"`
		InPool     bool    `json:"in_pool"`
		Strikes    int     `json:"strikes"`
		OKRounds   int     `json:"ok_rounds"`
		Passive    *struct {
			ActiveConns int `json:"active_conns"`
		} `json:"passive"`
	} `json:"nodes"`
}

type transitionsResp struct {
	Transitions []struct {
		At      string   `json:"at"`
		Type    string   `json:"type"`
		Added   []string `json:"added"`
		Removed []string `json:"removed"`
	} `json:"transitions"`
}

// nodeHealthLite is the subset of NodeHealth the record keeps for the probe
// terminal's primary/secondary.
type nodeHealthLite struct {
	RTTP50     int     `json:"rtt_p50_ms"`
	RTTP95     int     `json:"rtt_p95_ms"`
	FailRate   float64 `json:"fail_rate"`
	ProbeCount int     `json:"probe_count"`
}

type terminalNodeResp struct {
	Name   string          `json:"name"`
	Alive  bool            `json:"alive"`
	Health *nodeHealthLite `json:"health"`
}

type terminalResp struct {
	IP         string            `json:"ip"`
	GroupName  string            `json:"group_name"`
	ActiveNode string            `json:"active_node"`
	Primary    *terminalNodeResp `json:"primary"`
	Secondary  *terminalNodeResp `json:"secondary"`
	Pools      []struct {
		Pool       string            `json:"pool"`
		GroupName  string            `json:"group_name"`
		ActiveNode string            `json:"active_node"`
		Primary    *terminalNodeResp `json:"primary"`
		Secondary  *terminalNodeResp `json:"secondary"`
	} `json:"pools"`
}

// sample collects one record. window is the time since the previous sample
// and scopes the journal/transition deltas.
func (s *sampler) sample(ctx context.Context, now time.Time, window time.Duration) Sample {
	sample := Sample{
		Direct: map[string]int{},
		Journal: JournalPart{
			LastDurationMs: 0,
		},
	}
	addErr := func(format string, args ...any) {
		if len(sample.Errors) < 8 {
			sample.Errors = append(sample.Errors, fmt.Sprintf(format, args...))
		}
	}

	// 1. Data-path assertion verdict.
	var h healthResp
	code, hms, err := getJSON(ctx, s.api, "/healthz", &h, s.currentToken())
	sample.Health.LatencyMs = hms
	switch {
	case err != nil:
		sample.Health.Err = err.Error()
		addErr("healthz: %v", err)
	case code == 503 && len(h.Checks) == 0 && h.Detail != "":
		sample.Health.OK = false
		sample.Health.Err = h.Detail
	default:
		sample.Health.OK = h.OK
		sample.Health.Scope = h.Scope
		for _, c := range h.Checks {
			if !c.OK {
				sample.Health.Failing = append(sample.Health.Failing, c.Name)
			}
		}
	}

	// 2. Pool status.
	var st statusResp
	if _, _, err := getJSON(ctx, s.api, "/api/status", &st, s.currentToken()); err != nil {
		addErr("status: %v", err)
	} else {
		sample.Pool = &PoolPart{
			Size: st.PoolSize, KTarget: st.PoolSizing.KTarget, KCurrent: st.PoolSizing.KCurrent,
			Tier1: st.PoolSizing.Tier1Count, Eligible: st.PoolEligible, Total: st.PoolTotal,
			NodeCount: st.NodeCount, SupplyLimited: st.PoolSizing.SupplyLimited,
			SizingMode: st.SizingMode, LastUpdate: st.PoolLast, LastRefresh: st.LastRefresh,
		}
	}

	// 3. Watchdog verdict.
	var wd watchdogResp
	if _, _, err := getJSON(ctx, s.api, "/api/watchdog/status", &wd, s.currentToken()); err == nil {
		sample.Watchdog = &Watchdog{Enabled: wd.Enabled, State: wd.State, Failing: wd.Failing}
	}

	// 4. In-pool node health.
	var nr nodesResp
	if _, _, err := getJSON(ctx, s.api, "/api/nodes/health", &nr, s.currentToken()); err != nil {
		addErr("nodes/health: %v", err)
	} else {
		for _, n := range nr.Nodes {
			if !n.InPool {
				continue
			}
			p := NodePart{
				Name: n.Name, Alive: n.Alive, RTTP50: n.RTTP50, RTTP95: n.RTTP95,
				Jitter: n.Jitter, FailRate: n.FailRate, ProbeCount: n.ProbeCount,
				Strikes: n.Strikes, OKRounds: n.OKRounds,
			}
			if n.Passive != nil {
				p.ActiveConns = n.Passive.ActiveConns
			}
			sample.Nodes = append(sample.Nodes, p)
		}
		sort.Slice(sample.Nodes, func(i, j int) bool { return sample.Nodes[i].Name < sample.Nodes[j].Name })
	}

	// 5. Churn: transitions recorded in this interval + rolling windows.
	var tr transitionsResp
	if _, _, err := getJSON(ctx, s.api, "/api/pool/transitions?limit=200", &tr, s.currentToken()); err != nil {
		addErr("transitions: %v", err)
	} else {
		ch := &ChurnPart{}
		nowUTC := now.UTC()
		for _, t := range tr.Transitions {
			at, perr := time.Parse(time.RFC3339Nano, t.At)
			if perr != nil {
				continue
			}
			age := nowUTC.Sub(at)
			if window > 0 && age <= window {
				ch.Interval++
			}
			if age <= 5*time.Minute {
				ch.Last5m++
			}
			if age <= 24*time.Hour {
				ch.Last24h++
			}
			if ch.LastAt == "" || t.At > ch.LastAt {
				ch.LastAt = t.At
				ch.Added = t.Added
				ch.Removed = t.Removed
			}
		}
		sample.Churn = ch
	}

	// 6. Terminal assignment (optional probe IP).
	group := ""
	if s.probeIP != "" {
		var term terminalResp
		path := "/api/pool/terminal?ip=" + url.QueryEscape(s.probeIP)
		if _, _, err := getJSON(ctx, s.api, path, &term, s.currentToken()); err != nil {
			addErr("terminal: %v", err)
		} else if term.GroupName != "" || term.Primary != nil {
			t := &TermPart{IP: term.IP, Group: term.GroupName, ActiveNode: term.ActiveNode}
			if term.Primary != nil {
				t.Primary, t.PrimaryOK = term.Primary.Name, term.Primary.Alive
				if h := term.Primary.Health; h != nil {
					t.PrimaryP50, t.PrimaryP95, t.PrimaryFail = h.RTTP50, h.RTTP95, h.FailRate
				}
			}
			if term.Secondary != nil {
				t.Secondary, t.SecondOK = term.Secondary.Name, term.Secondary.Alive
				if h := term.Secondary.Health; h != nil {
					t.SecondP50, t.SecondP95, t.SecondFail = h.RTTP50, h.RTTP95, h.FailRate
				}
			}
			for _, p := range term.Pools {
				pa := PoolAssign{Pool: p.Pool, Group: p.GroupName, ActiveNode: p.ActiveNode}
				if p.Primary != nil {
					pa.Primary, pa.PrimaryOK = p.Primary.Name, p.Primary.Alive
					if h := p.Primary.Health; h != nil {
						pa.PrimaryP50, pa.PrimaryP95 = h.RTTP50, h.RTTP95
					}
				}
				if p.Secondary != nil {
					pa.Secondary, pa.SecondOK = p.Secondary.Name, p.Secondary.Alive
				}
				t.Pools = append(t.Pools, pa)
			}
			sample.Terminal = t
			group = term.GroupName
		}
	}

	// 7. Rendered config: the per-unit fallback regression (1027 groups) and
	// reload timing are visible here.
	if s.confPath != "" {
		mt, size, fallbacks, perterm, err := scanConfig(s.confPath)
		if err != nil {
			addErr("config: %v", err)
		} else {
			sample.Reload.ConfigMtime = mt.Format(time.RFC3339)
			sample.Reload.ConfigBytes = size
			sample.Reload.FallbackGroups = fallbacks
			sample.Reload.PerTermRules = perterm
			sample.Reload.ConfigChanged = !s.lastMtime.IsZero() && !mt.Equal(s.lastMtime)
			s.lastMtime = mt
		}
	}

	// 8. Journal deltas.
	gwSince := now.Add(-window)
	gwText, err := scanJournal(ctx, "turnout-gateway", gwSince)
	if err != nil {
		addErr("journal gateway: %v", err)
	} else {
		sample.Journal.HotReloads = countLogSignals(gwText, "hot-reloaded")
		sample.Journal.HotReloadFails = countLogSignals(gwText, "hot-reload failed")
		sample.Journal.ScoredRounds = countLogSignals(gwText, "nodescorer: scored")
		sample.Journal.WarmupSkips = countLogSignals(gwText, "warming up")
		sample.Journal.GatewayWarns = countLogSignals(gwText, "level=warn")
		sample.Journal.GatewayErrors = countLogSignals(gwText, "level=error")
		sample.Journal.LastDurationMs = lastReloadDuration(gwText)
		sample.Reload.HotReloads = sample.Journal.HotReloads
		sample.Reload.HotReloadFails = sample.Journal.HotReloadFails
		sample.Reload.ScoredRounds = sample.Journal.ScoredRounds
		sample.Reload.WarmupSkips = sample.Journal.WarmupSkips
		sample.Reload.LastDurationMs = sample.Journal.LastDurationMs
		routing, probing, named, namedDeferred := lastScoredFlags(gwText)
		sample.Reload.RoutingChanged = routing
		sample.Reload.ProbingChanged = probing
		sample.Reload.NamedChanged = named
		sample.Reload.NamedDeferred = namedDeferred
	}
	miText, err := scanJournal(ctx, "turnout-mihomo", gwSince)
	if err != nil {
		addErr("journal mihomo: %v", err)
	} else {
		sample.Journal.MihomoWarns = countLogSignals(miText, "level=warning")
		sample.Journal.MihomoErrors = countLogSignals(miText, "level=error")
		sample.Journal.DNSFailures = countLogSignals(miText, "can't resolve ip") +
			countLogSignals(gwText, "SERVFAIL")
	}

	// 9. DNS through the gateway's own resolver, rotating the domain.
	if domain := s.nextDomain(); domain != "" {
		ms, cached, err := lookupThroughResolver(s.dnsAddr, domain, 6*time.Second)
		d := &DNSPart{Domain: domain, Ms: ms, Cached: cached, OK: err == nil}
		if err != nil {
			d.Err = err.Error()
		}
		sample.DNS = d
	}

	// 10. Direct DNS reachability (the 2026-10-24 failure mode).
	sample.Direct = probeDirectDNS()

	// 11. End-to-end proxy delay through the probe terminal's pair group.
	// Only when the assignment is known: default-pool is a candidate-wide
	// load-balancer, NOT the path an in-subnet terminal takes, and during
	// startup its hash pick produced false "proxy failed" samples.
	if group != "" {
		ms, perr := proxyDelay(ctx, s.clash, group, "https://www.youtube.com", 5*time.Second)
		p := &ProxyPart{Group: group, URL: "https://www.youtube.com", Ms: ms, OK: perr == nil}
		if perr != nil {
			p.Err = perr.Error()
		}
		sample.Proxy = p
	}

	// 12. Resources.
	sample.Res = readResources()

	return sample
}

// scanConfig returns mtime/size plus the two counts that make renderer
// regressions visible: fallback group count and per-terminal rule count.
func scanConfig(path string) (time.Time, int64, int, int, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, 0, 0, 0, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, 0, 0, 0, err
	}
	text := string(data)
	return fi.ModTime(), fi.Size(), strings.Count(text, "type: fallback"), strings.Count(text, "SRC-IP-"), nil
}

func readResources() ResPart {
	r := ResPart{
		MihomoRSSMB:  rssMB("mihomo"),
		GatewayRSSMB: rssMB("turnout-gateway"),
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		var load1 float64
		_, _ = fmt.Sscanf(string(b), "%f", &load1)
		r.Load1 = load1
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "MemAvailable:") {
				var kb int64
				_, _ = fmt.Sscanf(line, "MemAvailable: %d kB", &kb)
				r.MemAvailMB = kb / 1024
				break
			}
		}
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/var/lib/turnout", &fs); err == nil {
		r.DiskFreeMB = int64(fs.Bavail) * int64(fs.Bsize) / (1024 * 1024)
	}
	return r
}

// prune deletes daily files older than retain.
func prune(dir string, retain time.Duration) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-retain)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "health-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day, err := time.ParseInLocation("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(name, "health-"), ".jsonl"), time.Local)
		if err != nil {
			continue
		}
		if day.Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, name))
		}
	}
}
