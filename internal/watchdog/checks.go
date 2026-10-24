// checks.go — the four self-checks the watchdog can run.
//
// Each check answers a distinct question about whether the bypass node can
// actually do its job. They are deliberately cheap: the watchdog runs every
// 10s by default, so anything expensive (the end-to-end egress probe) is off
// by default and opt-in.
//
// The checks share a design rule: report what was observed, and never repair.
// Repair belongs to dataplane/assert.go (for the rule objects) and to the
// engine's own supervision (for the process). A checker that also fixed
// things would make the verdict uninterpretable and fight the repair path —
// see the package doc.

package watchdog

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/dataplane"
)

// RuleStateSource reports the TPROXY rule assertion state. Implemented by
// dataplane.Asserter via Snapshot(). An interface rather than a concrete
// *Asserter so the watchdog does not care whether the asserter is running;
// a nil source yields a skipped check.
type RuleStateSource interface {
	Snapshot() dataplane.Snapshot
}

// PoolStateSource reports how many egress nodes are currently healthy.
// Implemented by nodescorer.Scorer via GetSnapshot().
type PoolStateSource interface {
	GetSnapshot() PoolSnapshot
}

// PoolSnapshot is the minimal view of the scorer the watchdog needs. Kept
// separate from nodescorer's full Snapshot so the watchdog package does not
// import nodescorer (which would pull the whole scoring machinery into its
// dependency graph and make tests slow).
type PoolSnapshot struct {
	Qualified int
	Total     int
	Alive     int
}

// ── engine_alive ────────────────────────────────────────────────────────────

// engineChecker verifies mihomo is up and answering its clash-api.
//
// It asks the API rather than checking for the process: a mihomo that is
// running but wedged (deadlocked, or bound but not serving) answers `pgrep`
// and not `/version`, and the wedged case is the one that black-holes traffic.
type engineChecker struct {
	addr   string
	secret string
	client *http.Client
}

// NewEngineChecker builds the engine liveness check against the clash-api
// address from data_plane.clash_api.
func NewEngineChecker(api config.ClashAPIConfig) Checker {
	return &engineChecker{
		addr:   api.ExternalController,
		secret: api.Secret,
		client: &http.Client{Timeout: 3 * time.Second},
	}
}

func (c *engineChecker) Name() CheckName { return CheckEngineAlive }

func (c *engineChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: CheckEngineAlive}
	if c.addr == "" {
		res.Skipped = true
		res.Detail = "no clash_api.external_controller configured"
		return res
	}
	url := "http://" + c.addr + "/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		res.Detail = fmt.Sprintf("build request: %v", err)
		return res
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		res.Detail = fmt.Sprintf("clash-api %s unreachable: %v", c.addr, err)
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		res.Detail = fmt.Sprintf("clash-api %s returned HTTP %d", c.addr, resp.StatusCode)
		return res
	}
	res.OK = true
	res.Detail = fmt.Sprintf("clash-api %s answering", c.addr)
	return res
}

// ── dataplane_rules ─────────────────────────────────────────────────────────

// rulesChecker reads dataplane/assert.go's verdict. It does NOT run the
// checks itself — see the package doc for why the split matters.
type rulesChecker struct {
	src RuleStateSource
}

// NewRulesChecker wraps an asserter (or anything exposing its Snapshot).
// A nil source produces a skipped check rather than a failing one: no
// asserter means there is nothing to assert against (e.g. TPROXY disabled),
// which is a configuration fact, not a fault.
func NewRulesChecker(src RuleStateSource) Checker {
	return &rulesChecker{src: src}
}

func (c *rulesChecker) Name() CheckName { return CheckDataplaneRules }

func (c *rulesChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: CheckDataplaneRules}
	if c.src == nil {
		res.Skipped = true
		res.Detail = "no data-path asserter configured"
		return res
	}
	snap := c.src.Snapshot()
	if snap.At.IsZero() {
		// The asserter has not completed a round yet. Not a failure —
		// reporting one here would trip the threshold on every restart.
		res.Skipped = true
		res.Detail = "asserter has not completed a round yet"
		return res
	}
	if snap.Healthy {
		res.OK = true
		res.Detail = fmt.Sprintf("all %d data-path checks passing (asserted %s ago)",
			len(snap.Checks), time.Since(snap.At).Round(time.Second))
		return res
	}
	// Summarize which checks failed, so the alert names the object.
	var bad []string
	for _, ck := range snap.Checks {
		if !ck.OK {
			d := string(ck.Name)
			if ck.Repaired {
				d += " (auto-repaired)"
			}
			bad = append(bad, d)
		}
	}
	res.Detail = fmt.Sprintf("data-path checks failing: %s", strings.Join(bad, ", "))
	return res
}

// ── pool_healthy ────────────────────────────────────────────────────────────

// poolChecker verifies at least N egress nodes are usable.
//
// This is the check that catches "everything is green but nothing works":
// process up, rules in place, and every airport node dead or evicted. With no
// healthy egress the classifier has nowhere to send whitelisted traffic, so
// proxied flows black-hole while every other signal looks fine.
type poolChecker struct {
	src PoolStateSource
	min int
}

// NewPoolChecker builds the egress-pool check. min <= 0 skips the check.
func NewPoolChecker(src PoolStateSource, min int) Checker {
	return &poolChecker{src: src, min: min}
}

func (c *poolChecker) Name() CheckName { return CheckPoolHealthy }

func (c *poolChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: CheckPoolHealthy}
	if c.min <= 0 {
		res.Skipped = true
		res.Detail = "disabled (pool_healthy_min <= 0)"
		return res
	}
	if c.src == nil {
		res.Skipped = true
		res.Detail = "no node scorer configured"
		return res
	}
	snap := c.src.GetSnapshot()
	// Before the first scoring round every counter is zero. Treat that as
	// skipped, not failed: a fresh start would otherwise report unhealthy
	// for the first scoring interval even though nothing is wrong yet.
	if snap.Total == 0 {
		res.Skipped = true
		res.Detail = "no scoring round has completed yet"
		return res
	}
	res.Detail = fmt.Sprintf("%d alive / %d total (need %d)", snap.Alive, snap.Total, c.min)
	if snap.Alive >= c.min {
		res.OK = true
		return res
	}
	res.Detail = fmt.Sprintf("only %d egress node(s) alive of %d (need %d) — proxied traffic has nowhere to go",
		snap.Alive, snap.Total, c.min)
	return res
}

// ── egress_probe ────────────────────────────────────────────────────────────

// egressChecker fetches a URL through mihomo's loopback proxy. It is the only
// check that proves the entire chain works end to end, and the only one that
// generates real traffic on every round — hence off by default.
//
// It dials the loopback HTTP inbound (mixed-port) rather than the TPROXY path
// because the TPROXY path requires a client packet to arrive on the ingress
// interface; originating one from this host would need an interface-bound
// socket and would itself look like the DIRECT path. The loopback inbound
// exercises everything downstream of classification: DNS, the out selector,
// the egress pool, and the airport node.
type egressChecker struct {
	proxyURL string
	target   string
	client   *http.Client
}

// NewEgressChecker builds the end-to-end probe. proxyURL is mihomo's loopback
// HTTP inbound (e.g. http://127.0.0.1:11080); target is the URL fetched.
func NewEgressChecker(proxyURL, target string, timeout time.Duration) Checker {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	parsed, _ := url.Parse(proxyURL)
	transport := &http.Transport{
		Proxy: http.ProxyURL(parsed),
		// The probe must not reuse a connection: a stale keep-alive would
		// report the previous round's success. Same reasoning as the site
		// probes' DisableKeepAlives fix.
		DisableKeepAlives: true,
	}
	return &egressChecker{
		proxyURL: proxyURL,
		target:   target,
		client:   &http.Client{Timeout: timeout, Transport: transport},
	}
}

func (c *egressChecker) Name() CheckName { return CheckEgressProbe }

func (c *egressChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: CheckEgressProbe}
	if c.target == "" {
		res.Skipped = true
		res.Detail = "no egress_probe_url configured"
		return res
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.target, nil)
	if err != nil {
		res.Detail = fmt.Sprintf("build request: %v", err)
		return res
	}
	// The probe only needs the status line. Asking for a body-less fetch is
	// what keeps the per-round cost negligible on an airport quota.
	req.Header.Set("Range", "bytes=0-0")
	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		res.Detail = fmt.Sprintf("probe via %s failed: %v", c.proxyURL, err)
		return res
	}
	defer resp.Body.Close()
	elapsed := time.Since(start).Round(time.Millisecond)
	// 2xx/3xx mean we got a real answer through the tunnel. 204 is the
	// expected value for generate_204.
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		res.OK = true
		res.Detail = fmt.Sprintf("HTTP %d via %s in %s", resp.StatusCode, c.proxyURL, elapsed)
		return res
	}
	res.Detail = fmt.Sprintf("probe returned HTTP %d via %s in %s", resp.StatusCode, c.proxyURL, elapsed)
	return res
}

// ── dns_resolve ─────────────────────────────────────────────────────────────

// dnsLookup resolves a domain and returns its addresses. Injectable so tests
// need no DNS server; production pins mihomo's own listener.
type dnsLookup func(ctx context.Context, domain string) ([]string, error)

type dnsChecker struct {
	addr    string
	domain  string
	timeout time.Duration
	lookup  dnsLookup
}

// NewDNSChecker builds the resolution check.
//
// addr is this node's DNS listener (node.ingress_ip:53, or the
// data_plane.dns.listen override). domain must resolve through proxy_doh —
// i.e. be a whitelisted overseas name — otherwise the check only exercises
// the domestic resolver and cannot see the failure mode it exists for.
//
// History: 2026-10-24, the office network began blocking direct access to
// the proxy_doh upstreams. Every whitelisted lookup returned SERVFAIL and
// users saw "cannot find the server IP address", while engine_alive,
// dataplane_rules and pool_healthy all stayed green — the watchdog had no
// signal for DNS at all.
func NewDNSChecker(addr, domain string, timeout time.Duration) Checker {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if domain == "" {
		domain = "www.youtube.com"
	}
	return &dnsChecker{
		addr:    addr,
		domain:  domain,
		timeout: timeout,
		lookup: func(ctx context.Context, name string) ([]string, error) {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
					// Pin to this node's listener: the system resolver on the
					// host points elsewhere and would test the wrong path.
					d := net.Dialer{}
					return d.DialContext(ctx, "udp", addr)
				},
			}
			return r.LookupHost(ctx, name)
		},
	}
}

func (c *dnsChecker) Name() CheckName { return CheckDNSResolve }

func (c *dnsChecker) Check(ctx context.Context) CheckResult {
	res := CheckResult{Name: CheckDNSResolve}
	if c.addr == "" {
		res.Skipped = true
		res.Detail = "no DNS listener address (set node.ingress_ip or data_plane.dns.listen)"
		return res
	}
	cctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	start := time.Now()
	addrs, err := c.lookup(cctx, c.domain)
	elapsed := time.Since(start).Round(time.Millisecond)
	if err != nil {
		res.Detail = fmt.Sprintf("resolve %s via %s failed after %s: %v", c.domain, c.addr, elapsed, err)
		return res
	}
	if len(addrs) == 0 {
		res.Detail = fmt.Sprintf("resolve %s via %s returned no addresses after %s", c.domain, c.addr, elapsed)
		return res
	}
	res.OK = true
	res.Detail = fmt.Sprintf("%s -> %s via %s in %s", c.domain, addrs[0], c.addr, elapsed)
	return res
}
