package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/apitls"
)

var httpClient = &http.Client{Timeout: 6 * time.Second}

// pinAPI makes httpClient accept only a TLS peer whose public key matches
// the certificate at certFile — the gateway's auto-managed self-signed
// certificate, which no trust store knows. Pinning the key rather than the
// certificate means the gateway's yearly renewal (same key) needs no
// restart here; only a key rotation does, and the gateway logs that.
func pinAPI(certFile string) error {
	pin, err := apitls.PinFromCertFile(certFile)
	if err != nil {
		return err
	}
	httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify:    true, // the pin below is the trust decision
		VerifyPeerCertificate: apitls.VerifyPin(pin),
	}}
	return nil
}

// getJSON fetches path from base and decodes into out. It reports the HTTP
// status and elapsed time; a non-2xx response still decodes (the gateway
// uses 503 bodies for unhealthy states, and those bodies are the record).
func getJSON(ctx context.Context, base, path string, out any, token string) (status int, ms int, err error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return 0, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, int(time.Since(start).Milliseconds()), err
	}
	defer resp.Body.Close()
	if out != nil {
		if derr := json.NewDecoder(resp.Body).Decode(out); derr != nil {
			return resp.StatusCode, int(time.Since(start).Milliseconds()), derr
		}
	}
	return resp.StatusCode, int(time.Since(start).Milliseconds()), nil
}

// lookupThroughResolver resolves name via the gateway's own DNS listener.
// PreferGo + custom Dial is the same mechanism dnspreload uses to warm the
// cache, so the latency measured here is what a terminal's first lookup pays.
func lookupThroughResolver(addr, name string, timeout time.Duration) (ms int, cached bool, err error) {
	if addr == "" {
		return 0, false, fmt.Errorf("no dns listener configured")
	}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	_, err = r.LookupHost(ctx, name)
	ms = int(time.Since(start).Milliseconds())
	return ms, ms <= 5, err
}

// tcpProbe dials addr and returns elapsed ms, or -1 when the dial failed.
// The 2026-10-24 outage was exactly this: direct DNS paths blocked while the
// airport pool stayed healthy, so the sampler records them independently of
// mihomo's own health.
func tcpProbe(addr string, timeout time.Duration) int {
	start := time.Now()
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return -1
	}
	_ = c.Close()
	return int(time.Since(start).Milliseconds())
}

// probeDirectDNS runs the direct-reachability probes in parallel.
func probeDirectDNS() map[string]int {
	targets := []string{"1.1.1.1:853", "1.1.1.1:443", "8.8.8.8:443"}
	out := make(map[string]int, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			ms := tcpProbe(addr, 2*time.Second)
			mu.Lock()
			out[addr] = ms
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return out
}

// proxyDelay asks mihomo to make one HTTP request through group and returns
// the measured delay. This is the only active end-to-end probe: everything
// else observes state.
func proxyDelay(ctx context.Context, clash, group, target string, timeout time.Duration) (int, error) {
	if group == "" {
		return 0, fmt.Errorf("no group")
	}
	if target == "" {
		target = "https://www.youtube.com"
	}
	path := "/proxies/" + url.PathEscape(group) + "/delay?url=" + url.QueryEscape(target) +
		"&timeout=" + strconv.Itoa(int(timeout.Milliseconds()))
	var resp struct {
		Delay   int    `json:"delay"`
		Message string `json:"message"`
	}
	code, _, err := getJSON(ctx, clash, path, &resp, "")
	if err != nil {
		return 0, err
	}
	if resp.Message != "" {
		return 0, fmt.Errorf("%s (http %d)", resp.Message, code)
	}
	return resp.Delay, nil
}

// scanJournal reads the unit's log since `since` and counts the signals the
// sampler records. journalctl is used instead of the journal files because
// the unit is systemd-owned and the output format is stable.
func scanJournal(ctx context.Context, unit string, since time.Time) (text string, err error) {
	out, err := exec.CommandContext(ctx, "journalctl", "-u", unit,
		"--since", since.Format(time.RFC3339),
		"--no-pager", "-o", "cat").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

var durationRe = regexp.MustCompile(`duration=([0-9.]+)(ms|s|µs|us)`)

// lastReloadDuration extracts the most recent hot-reload duration from a
// journal slice. Returns 0 when no reload line is present.
func lastReloadDuration(text string) int {
	matches := durationRe.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return 0
	}
	m := matches[len(matches)-1]
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	switch m[2] {
	case "s":
		return int(v * 1000)
	case "µs", "us":
		return int(v / 1000)
	default:
		return int(v)
	}
}

// lastScoredFlags extracts the change attribution from the most recent
// "nodescorer: scored" line in a journal slice. The gateway emits
// routing_changed / named_changed / named_deferred alongside the historical
// pool_changed / default_pool_changed flags (added 2026-10-25); an older
// binary omits them and every value reads false.
func lastScoredFlags(text string) (routing, probing, named, namedDeferred bool) {
	idx := strings.LastIndex(text, "nodescorer: scored")
	if idx < 0 {
		return
	}
	line := text[idx:]
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	return strings.Contains(line, "routing_changed=true"),
		strings.Contains(line, "default_pool_changed=true"),
		strings.Contains(line, "named_changed=true"),
		strings.Contains(line, "named_deferred=true")
}

// countLogSignals counts lines containing each needle (case-insensitive).
func countLogSignals(text string, needles ...string) int {
	if text == "" {
		return 0
	}
	lower := strings.ToLower(text)
	n := 0
	for _, needle := range needles {
		n += strings.Count(lower, strings.ToLower(needle))
	}
	return n
}

// rssMB finds the process whose comm matches name and returns its resident
// set in MiB. Scans /proc rather than shelling out to ps so the sampler has
// no dependency on procps.
func rssMB(name string) float64 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	for _, e := range entries {
		if !e.IsDir() || !allDigits(e.Name()) {
			continue
		}
		stat, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// comm sits between the first '(' and the last ')' — it can contain
		// spaces and parentheses, so split on the last ')'.
		open := strings.IndexByte(string(stat), '(')
		closeIdx := strings.LastIndexByte(string(stat), ')')
		if open < 0 || closeIdx <= open {
			continue
		}
		if strings.TrimSpace(string(stat[open+1:closeIdx])) != name {
			continue
		}
		statm, err := os.ReadFile("/proc/" + e.Name() + "/statm")
		if err != nil {
			continue
		}
		fields := strings.Fields(string(statm))
		if len(fields) < 2 {
			continue
		}
		pages, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		return pages * 4096 / (1024 * 1024)
	}
	return 0
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
