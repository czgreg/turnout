package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// summary holds the aggregates printSummary derives from the JSONL records.
// Everything is additive over samples, so a gap (sampler down) simply lowers
// the sample count instead of corrupting the rates.
type summary struct {
	samples     int
	first, last time.Time

	hotReloads     int
	hotReloadFails int
	scoredRounds   int
	warmupSkips    int
	reloadDurMax   int
	reloadDurSum   int
	reloadDurN     int

	transitions int

	// Change attribution, counted once per scoring round seen in a sample
	// window. A round can set routing and probing together; named applied and
	// named deferred are mutually exclusive for one round.
	routingChanges int
	probingChanges int
	namedApplied   int
	namedDeferred  int

	// Probe-terminal pairs whose primary and secondary share a subscription
	// (the "sub/name" tag prefix). Before cross-subscription secondaries this
	// was 99.4% (2026-10-26/27) — one airport ingress outage took both down.
	pairs, pairsSameSub     int
	aiPairs, aiPairsSameSub int

	dnsTotal, dnsOK, dnsCached int
	dnsLatencies               []int

	directTotal map[string]int
	directFails map[string]int

	proxyTotal, proxyOK int
	proxyLatencies      []int

	fallbackMin, fallbackMax int
	fallbackSum, fallbackN   int

	rssMax, rssSum float64
	rssN           int

	gwWarns, gwErrors int
	miWarns, miErrors int
	dnsFailures       int
	healthBad         int
}

func (s *summary) add(rec Sample) {
	s.samples++
	if ts, err := time.Parse(time.RFC3339, rec.TS); err == nil {
		if s.first.IsZero() || ts.Before(s.first) {
			s.first = ts
		}
		if ts.After(s.last) {
			s.last = ts
		}
	}
	s.hotReloads += rec.Journal.HotReloads
	s.hotReloadFails += rec.Journal.HotReloadFails
	s.scoredRounds += rec.Journal.ScoredRounds
	s.warmupSkips += rec.Journal.WarmupSkips
	if d := rec.Journal.LastDurationMs; d > 0 {
		if d > s.reloadDurMax {
			s.reloadDurMax = d
		}
		s.reloadDurSum += d
		s.reloadDurN++
	}
	if rec.Churn != nil {
		s.transitions += rec.Churn.Interval
	}
	if rec.Reload.RoutingChanged {
		s.routingChanges++
	}
	if rec.Reload.ProbingChanged {
		s.probingChanges++
	}
	if rec.Reload.NamedChanged {
		s.namedApplied++
	}
	if rec.Reload.NamedDeferred {
		s.namedDeferred++
	}
	if t := rec.Terminal; t != nil {
		if t.Primary != "" && t.Secondary != "" {
			s.pairs++
			if subscriptionOf(t.Primary) == subscriptionOf(t.Secondary) {
				s.pairsSameSub++
			}
		}
		for _, p := range t.Pools {
			if p.Primary != "" && p.Secondary != "" {
				s.aiPairs++
				if subscriptionOf(p.Primary) == subscriptionOf(p.Secondary) {
					s.aiPairsSameSub++
				}
			}
		}
	}
	if rec.DNS != nil {
		s.dnsTotal++
		if rec.DNS.OK {
			s.dnsOK++
			s.dnsLatencies = append(s.dnsLatencies, rec.DNS.Ms)
		}
		if rec.DNS.Cached {
			s.dnsCached++
		}
	}
	if s.directTotal == nil {
		s.directTotal = map[string]int{}
		s.directFails = map[string]int{}
	}
	for addr, ms := range rec.Direct {
		s.directTotal[addr]++
		if ms < 0 {
			s.directFails[addr]++
		}
	}
	if rec.Proxy != nil {
		s.proxyTotal++
		if rec.Proxy.OK {
			s.proxyOK++
			s.proxyLatencies = append(s.proxyLatencies, rec.Proxy.Ms)
		}
	}
	if g := rec.Reload.FallbackGroups; g > 0 {
		if s.fallbackMin == 0 || g < s.fallbackMin {
			s.fallbackMin = g
		}
		if g > s.fallbackMax {
			s.fallbackMax = g
		}
		s.fallbackSum += g
		s.fallbackN++
	}
	if r := rec.Res.MihomoRSSMB; r > 0 {
		if r > s.rssMax {
			s.rssMax = r
		}
		s.rssSum += r
		s.rssN++
	}
	s.gwWarns += rec.Journal.GatewayWarns
	s.gwErrors += rec.Journal.GatewayErrors
	s.miWarns += rec.Journal.MihomoWarns
	s.miErrors += rec.Journal.MihomoErrors
	s.dnsFailures += rec.Journal.DNSFailures
	if !rec.Health.OK {
		s.healthBad++
	}
}

func pct(v []int, p float64) int {
	if len(v) == 0 {
		return 0
	}
	cp := append([]int(nil), v...)
	sort.Ints(cp)
	// Nearest-rank: ceil(p*n)-1. With 5 samples, p95 is the 5th, p50 the 3rd.
	idx := int(math.Ceil(p*float64(len(cp)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func avgInt(sum, n int) int {
	if n == 0 {
		return 0
	}
	return sum / n
}

func avgFloat(sum float64, n int) float64 {
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

// printSummary reads records in the window and prints the aggregate. This is
// the "后续根据记录优化" entry point: one command answers whether churn, DNS,
// reloads or resource pressure changed.
func printSummary(dir string, window time.Duration, w io.Writer) error {
	cutoff := time.Now().Add(-window)
	files, err := filepath.Glob(filepath.Join(dir, "health-*.jsonl"))
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no records under %s", dir)
	}
	sort.Strings(files)
	var agg summary
	for _, path := range files {
		// Skip files whose day predates the window (name is the local date).
		day, derr := time.ParseInLocation("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "health-"), ".jsonl"), time.Local)
		if derr == nil && day.Add(24*time.Hour).Before(cutoff) {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			var rec Sample
			if json.Unmarshal(sc.Bytes(), &rec) != nil {
				continue
			}
			ts, err := time.Parse(time.RFC3339, rec.TS)
			if err != nil || ts.Before(cutoff) {
				continue
			}
			agg.add(rec)
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	if agg.samples == 0 {
		return fmt.Errorf("no samples in the last %s", window)
	}

	fmt.Fprintf(w, "healthwatch summary — last %s\n", window)
	fmt.Fprintf(w, "  window        %s → %s  (%d samples)\n",
		agg.first.Format("2006-01-02 15:04:05"), agg.last.Format("2006-01-02 15:04:05"), agg.samples)
	fmt.Fprintf(w, "  health        %d/%d samples unhealthy\n", agg.healthBad, agg.samples)
	fmt.Fprintf(w, "  reloads       %d hot reloads (%d failed), scored rounds %d, warm-up skips %d\n",
		agg.hotReloads, agg.hotReloadFails, agg.scoredRounds, agg.warmupSkips)
	if agg.reloadDurN > 0 {
		fmt.Fprintf(w, "  reload time   avg %d ms, max %d ms\n", avgInt(agg.reloadDurSum, agg.reloadDurN), agg.reloadDurMax)
	}
	fmt.Fprintf(w, "  pool churn    %d transitions observed (%.1f/h)\n",
		agg.transitions, float64(agg.transitions)/window.Hours())
	fmt.Fprintf(w, "  change cause  routing %d | probing %d | named applied %d | named deferred %d (rounds observed)\n",
		agg.routingChanges, agg.probingChanges, agg.namedApplied, agg.namedDeferred)
	if agg.pairs > 0 || agg.aiPairs > 0 {
		fmt.Fprintf(w, "  pair same-sub default %s | class pools %s (probe terminal; lower = failover survives one ingress)\n",
			ratio(agg.pairsSameSub, agg.pairs), ratio(agg.aiPairsSameSub, agg.aiPairs))
	}
	if agg.fallbackN > 0 {
		fmt.Fprintf(w, "  fallback grps min %d / avg %.0f / max %d\n",
			agg.fallbackMin, avgFloat(float64(agg.fallbackSum), agg.fallbackN), agg.fallbackMax)
	}
	if agg.dnsTotal > 0 {
		fmt.Fprintf(w, "  dns           %d/%d ok, cached %d, p50 %d ms, p95 %d ms\n",
			agg.dnsOK, agg.dnsTotal, agg.dnsCached, pct(agg.dnsLatencies, 0.50), pct(agg.dnsLatencies, 0.95))
	}
	for _, addr := range sortedKeys(agg.directTotal) {
		fails := agg.directFails[addr]
		fmt.Fprintf(w, "  direct %-12s %d/%d failed\n", addr, fails, agg.directTotal[addr])
	}
	if agg.proxyTotal > 0 {
		fmt.Fprintf(w, "  proxy         %d/%d ok, p50 %d ms, p95 %d ms (https://www.youtube.com)\n",
			agg.proxyOK, agg.proxyTotal, pct(agg.proxyLatencies, 0.50), pct(agg.proxyLatencies, 0.95))
	}
	if agg.rssN > 0 {
		fmt.Fprintf(w, "  mihomo rss    avg %.0f MB, max %.0f MB\n", avgFloat(agg.rssSum, agg.rssN), agg.rssMax)
	}
	fmt.Fprintf(w, "  journal       gateway warn %d err %d | mihomo warn %d err %d | dns resolve failures %d\n",
		agg.gwWarns, agg.gwErrors, agg.miWarns, agg.miErrors, agg.dnsFailures)
	return nil
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// subscriptionOf returns the "<subscription>" prefix of a "<subscription>/<name>"
// node tag (mirrors mihomo.SubscriptionOf; the sampler does not import it).
func subscriptionOf(tag string) string {
	if i := strings.IndexByte(tag, '/'); i > 0 {
		return tag[:i]
	}
	return tag
}

func ratio(n, d int) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%d/%d (%.1f%%)", n, d, 100*float64(n)/float64(d))
}
