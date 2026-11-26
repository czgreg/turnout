package subscribe

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// Manager owns subscriptions and the latest aggregated outbound list.
type Manager struct {
	entries []config.SubscriptionEntry
	fetcher *fetcher
	// globalUA is the configured Subscribe.UserAgent — captured here so the
	// UA-discovery fallback in Refresh can decide which alternate UA to try
	// without re-reading config every time.
	globalUA string

	mu            sync.RWMutex
	lastResults   []SubscriptionResult
	lastRefreshed time.Time
	lastHealth    []SubscriptionHealth

	// onUADiscovered is called (synchronously, off the refresh goroutine)
	// when Refresh's auto-fallback discovered a per-subscription UA that
	// works. The callback's job is to persist the discovery (e.g. write
	// back to gateway.yaml via configstore.Mutate) so future refreshes go
	// straight to the right UA without paying the discovery cost again.
	// Nil disables persistence — discovery still works in-memory.
	onUADiscovered func(name, ua string)

	// exclude drops matching tags from AllOutbounds — the feed of every
	// render and of the scorer — while Snapshot keeps them, so /api/nodes
	// and node counts still show what the provider served. Nil = keep all.
	// See config.URLTestConfig.NodeExcludePattern.
	exclude *regexp.Regexp

	// UA selection state, in memory only (see Refresh). Keyed by
	// subscription name; guarded by mu.
	uaChoice  map[string]uaChoice // auto-UA entries: the probed winner
	uaAdvice  map[string]uaChoice // explicit-UA entries: best alternative seen
	prevCount map[string]int      // node count of the last round that had nodes
	now       func() time.Time    // test hook; nil = time.Now

	// lastGood is the most recent parse that produced nodes, per
	// subscription, keyed by lastGoodKey (name + URL, so editing a
	// subscription's URL never resurrects the old URL's nodes). A
	// fetch_error round reuses it instead of dropping the subscription from
	// the render. Before this, one failed fetch took every node of that
	// provider out of mihomo until someone refreshed again, and with
	// refresh_interval: 0s nothing does: hutao's 429s on 6.15 (2026-10-24)
	// each removed all hutao nodes. Parse errors and zero-node answers do
	// NOT fall back: the upstream answered, and its answer wins. In memory
	// only, so a process restart starts empty. Guarded by mu.
	lastGood map[string]SubscriptionResult
}

// NewManagerWithFetch lets callers thread http_timeout and user_agent from
// config — many subscription providers gate by UA, so the default
// "turnout-gateway/0.1" gets connection-reset on some upstreams.
func NewManagerWithFetch(entries []config.SubscriptionEntry, timeout time.Duration, ua string) *Manager {
	return NewManagerWithFetchAndProxy(entries, timeout, ua, "")
}

// NewManagerWithFetchAndProxy is NewManagerWithFetch + proxyURL routing.
// Production wires this with the local mihomo loopback HTTP inbound
// (TurnoutInternalProxyURL) so subscription fetches egress through the pool
// instead of dialing overseas subscription hosts directly into the GFW,
// where they time out. Caught in production 2026-06-05.
//
// Empty proxyURL → direct OS network (used by tests + standalone CLIs).
func NewManagerWithFetchAndProxy(entries []config.SubscriptionEntry, timeout time.Duration, ua, proxyURL string) *Manager {
	return &Manager{
		entries:  entries,
		fetcher:  newFetcherWithProxy(timeout, ua, proxyURL),
		globalUA: ua,
	}
}

// WithUADiscoveryCallback registers a callback invoked when Refresh's
// auto-fallback finds a working per-subscription UA. Returns the receiver
// for chaining at construction.
func (m *Manager) WithUADiscoveryCallback(cb func(name, ua string)) *Manager {
	m.mu.Lock()
	m.onUADiscovered = cb
	m.mu.Unlock()
	return m
}

// WithNodeExclude sets data_plane.url_test.node_exclude_pattern. An empty
// pattern excludes nothing. config.Load has already rejected an invalid one;
// the error return covers callers that skip it.
func (m *Manager) WithNodeExclude(pattern string) (*Manager, error) {
	var re *regexp.Regexp
	if pattern != "" {
		var err error
		if re, err = regexp.Compile(pattern); err != nil {
			return m, fmt.Errorf("node_exclude_pattern: %w", err)
		}
	}
	m.mu.Lock()
	m.exclude = re
	m.mu.Unlock()
	return m, nil
}

// SubscriptionHealth is the per-subscription outcome of one Refresh round.
// Recorded for EVERY enabled entry, including the ones that failed — unlike
// lastResults, which only carries the successes.
//
// Why this exists: before it, a single subscription's transient fetch error
// was observable only as one generic "subscribe refresh had errors" warn
// line, and RunRefresh alerted only when EVERY subscription produced zero
// nodes. A 403 on one of five subscriptions was therefore indistinguishable
// from a clean round at the alerting layer. On 2026-09-08 that let Hutao sit
// at 0 nodes for 17.5 hours: the 403 landed 11s after a process restart, the
// operator had no signal, and refresh_interval: 0s meant nothing retried.
type SubscriptionHealth struct {
	Name string
	// Outcome is one of: "ok", "fetch_error", "parse_error", "zero_nodes".
	Outcome string
	// NodeCount is the parsed node count (0 for every non-ok outcome).
	NodeCount int
	// Err is the failure detail, empty when Outcome == "ok".
	Err string
	// UserInfo carries the traffic-quota and expiry metadata the airport
	// returned in the Subscription-Userinfo response header, if present.
	// Nil when the header was absent or unparseable (including on errors).
	UserInfo *UserInfo
	// GatedCount is how many client-gating pseudo-nodes the filter dropped
	// from this round's response ("please use FlClash", "your core does not
	// support AnyTLS"). Non-zero with Outcome == "ok" is normal — providers
	// append the hint alongside real nodes. Non-zero with Outcome ==
	// "zero_nodes" means the provider refused to serve our client at all,
	// which retrying with a newer UA can fix.
	GatedCount int
	// EffectiveUA is the User-Agent whose response this round used — the
	// probed winner for an auto-UA entry, the explicit one otherwise.
	EffectiveUA string
	// TypeCounts is NodeCount broken down by protocol ("hysteria2": 33).
	TypeCounts map[string]int
	// PrevNodeCount is the node count of the previous round that produced
	// nodes; 0 when there is none yet (first round since start).
	PrevNodeCount int
	// NodeDrop is true when NodeCount > 0 but fell below nodeDropRatio of
	// PrevNodeCount even after re-probing UAs. Catches silent partial loss
	// (a provider downgrading what it serves) that "ok" would hide.
	NodeDrop bool
	// SuggestedUA is set only for an entry with an explicit user_agent, when
	// another candidate UA yields more nodes (SuggestedNodeCount). The
	// explicit UA is still the one in use; switching is the operator's call.
	SuggestedUA        string
	SuggestedNodeCount int
	// StaleNodes is how many nodes a fetch_error round carried over from the
	// subscription's last successful fetch (see Manager.lastGood). 0 when
	// there was nothing to carry over, and for every other outcome.
	StaleNodes int
}

// LastHealth returns the per-subscription outcome of the most recent Refresh.
// Empty before the first Refresh completes.
func (m *Manager) LastHealth() []SubscriptionHealth {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SubscriptionHealth, len(m.lastHealth))
	copy(out, m.lastHealth)
	return out
}

// Refresh fetches every enabled subscription and parses it. Errors per
// subscription are logged but do not abort the whole refresh.
//
// UA selection. Providers gate subscriptions on the client the User-Agent
// claims to be, and they do it in at least three shapes:
//   - answer the "wrong" UA with HTTP 5xx (ash),
//   - answer with 200 + zero real nodes (yuyun; hutao's "please use FlClash"
//     pseudo-nodes, which the filter strips),
//   - answer with 200 + a DOWNGRADED list: only the protocols the claimed
//     core supports. wodi (2026-11) served ClashforWindows everything except
//     its 33 hysteria2 nodes — including all 9 US nodes — because CFW's
//     Premium core predates hy2. Nothing failed, so a failure-triggered
//     fallback never ran.
//
// The third shape is why selection is by comparison, not by failure: for an
// entry with no explicit UserAgent, Refresh fetches with every candidate UA
// and keeps the one that yields the most usable nodes after parsing. The
// parser only keeps protocols the data plane can run, so "most nodes" is a
// protocol-agnostic proxy for "least downgraded" — no per-provider or
// per-protocol rules.
//
// The winner is cached in memory for uaProbeTTL so steady-state rounds cost
// one request. The cache is re-validated early when the cached UA errors,
// yields nothing, or its node count drops by more than nodeDropRatio versus
// the previous round (the provider may have changed what it serves that UA).
// Nothing is written back to yaml — subscriptions[] is operator-owned.
//
// An entry WITH an explicit UserAgent is never switched. Its alternatives are
// probed at the same low frequency and, if one yields more nodes, the result
// is reported as SuggestedUA so the operator can decide.
//
// 4xx on the primary fetch is a token/auth problem; no UA will fix it, so no
// probing happens.
//
// Failure handling. A primary fetch that times out (dial, TLS, headers, or a
// stalled body) is retried once; an HTTP status answer, 429 included, is not.
// A subscription whose fetch still fails keeps its last good nodes (see
// Manager.lastGood) and reports them as StaleNodes.
func (m *Manager) Refresh(ctx context.Context) ([]SubscriptionResult, error) {
	m.mu.Lock()
	if m.uaChoice == nil {
		m.uaChoice = map[string]uaChoice{}
	}
	if m.uaAdvice == nil {
		m.uaAdvice = map[string]uaChoice{}
	}
	if m.prevCount == nil {
		m.prevCount = map[string]int{}
	}
	if m.now == nil {
		m.now = time.Now
	}
	prevGood := m.lastGood
	m.mu.Unlock()

	results := make([]SubscriptionResult, 0, len(m.entries))
	health := make([]SubscriptionHealth, 0, len(m.entries))
	good := make(map[string]SubscriptionResult, len(m.entries))
	var firstErr error
	for _, e := range m.entries {
		if !e.Enabled {
			continue
		}
		key := lastGoodKey(e)
		a, prev, drop, suggested := m.refreshEntry(ctx, e)
		if a.fetchErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("fetch %s: %w", e.Name, a.fetchErr)
			}
			h := SubscriptionHealth{
				Name: e.Name, Outcome: "fetch_error", Err: a.fetchErr.Error(), EffectiveUA: a.ua,
				PrevNodeCount: prev, SuggestedUA: suggested.ua, SuggestedNodeCount: suggested.nodes}
			if last, ok := prevGood[key]; ok {
				h.StaleNodes = len(last.Outbounds)
				good[key] = last
				results = append(results, last)
			}
			health = append(health, h)
			continue
		}
		if a.parseErr != nil {
			if firstErr == nil {
				firstErr = a.parseErr
			}
			health = append(health, SubscriptionHealth{
				Name: e.Name, Outcome: "parse_error", Err: a.parseErr.Error(), UserInfo: a.userInfo(),
				EffectiveUA: a.ua, PrevNodeCount: prev,
				SuggestedUA: suggested.ua, SuggestedNodeCount: suggested.nodes})
			continue
		}
		outcome := "ok"
		if len(a.parsed.Outbounds) == 0 {
			// Fetched and parsed cleanly but yielded nothing, with every
			// candidate UA (or the operator's explicit one). Distinct from
			// fetch_error: the upstream answered, so this is UA gating, an
			// emptied subscription, or a revoked token.
			outcome = "zero_nodes"
		}
		health = append(health, SubscriptionHealth{
			Name: e.Name, Outcome: outcome, NodeCount: len(a.parsed.Outbounds),
			UserInfo: a.userInfo(), GatedCount: a.gated,
			EffectiveUA: a.ua, TypeCounts: typeCounts(a.parsed.Outbounds),
			PrevNodeCount: prev, NodeDrop: drop,
			SuggestedUA: suggested.ua, SuggestedNodeCount: suggested.nodes})
		results = append(results, a.parsed)
		if len(a.parsed.Outbounds) > 0 {
			good[key] = a.parsed
		}
	}
	m.mu.Lock()
	m.lastResults = results
	m.lastRefreshed = time.Now()
	m.lastHealth = health
	// Rebuilt from this round only, so disabled, deleted, re-pointed and
	// answered-but-empty subscriptions drop out of it.
	m.lastGood = good
	m.mu.Unlock()
	return results, firstErr
}

// lastGoodKey keys Manager.lastGood by name and URL.
func lastGoodKey(e config.SubscriptionEntry) string {
	return e.Name + "\x00" + e.URL
}

// isTimeout reports whether err is a client-side timeout (dial, TLS,
// awaiting headers, or a body that stalled), as opposed to an answer.
func isTimeout(err error) bool {
	if err == nil || AsHTTPError(err) != nil {
		return false
	}
	var ne net.Error
	return (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, context.DeadlineExceeded)
}

// uaProbeTTL is how long an auto-selected UA (or an explicit-UA advisory) is
// trusted before Refresh compares all candidates again. A day keeps the
// extra upstream load to a handful of requests per subscription per day
// while still noticing a provider that changes what it serves each UA.
const uaProbeTTL = 24 * time.Hour

// nodeDropRatio: a round whose node count falls below this fraction of the
// previous successful round counts as a drop. On an auto-UA entry it forces
// an immediate re-probe; whatever remains after that is reported as NodeDrop.
const nodeDropRatio = 0.8

// uaChoice is a remembered probe result: which UA won, for which URL (a URL
// edit invalidates it), when, and with how many nodes.
type uaChoice struct {
	ua    string
	url   string
	at    time.Time
	nodes int
}

// uaAttempt is one fetch+parse with a given UA.
type uaAttempt struct {
	ua       string
	fr       *FetchResult
	parsed   SubscriptionResult
	gated    int
	fetchErr error
	parseErr error
}

func (a uaAttempt) nodes() int {
	if a.fetchErr != nil || a.parseErr != nil {
		return 0
	}
	return len(a.parsed.Outbounds)
}

func (a uaAttempt) userInfo() *UserInfo {
	if a.fr == nil {
		return nil
	}
	return a.fr.UserInfo
}

func (m *Manager) attempt(ctx context.Context, e config.SubscriptionEntry, ua string) uaAttempt {
	a := uaAttempt{ua: ua}
	a.fr, a.fetchErr = m.fetcher.GetWithUA(ctx, e.URL, ua)
	if a.fetchErr == nil {
		a.parsed, a.gated, a.parseErr = parseBytesStats(e.Name, e.Format, a.fr.Body)
	}
	return a
}

// refreshEntry runs the UA selection for one entry and returns the attempt
// whose result this round uses, the previous round's node count, whether
// the final count is a drop versus it, and any advisory UA for an entry
// with an explicit UserAgent.
func (m *Manager) refreshEntry(ctx context.Context, e config.SubscriptionEntry) (uaAttempt, int, bool, uaChoice) {
	m.mu.RLock()
	cached, haveCache := m.uaChoice[e.Name]
	prev := m.prevCount[e.Name]
	now := m.now()
	m.mu.RUnlock()
	if haveCache && cached.url != e.URL {
		haveCache = false
	}

	explicit := e.UserAgent != ""
	ua := e.UserAgent
	if !explicit {
		ua = m.globalUA
		if haveCache {
			ua = cached.ua
		}
	}
	a := m.attempt(ctx, e, ua)
	// One retry, on timeout only, and only for the primary fetch: a slow
	// provider often answers the second time, while a 4xx/5xx (429
	// included) is an answer, and repeating it at once only deepens a rate
	// limit. UA probes are not retried; they are skipped on transport
	// errors anyway (see shouldProbe).
	if isTimeout(a.fetchErr) && ctx.Err() == nil {
		slog.Info("subscribe: fetch timed out, retrying once", "name", e.Name, "err", a.fetchErr)
		a = m.attempt(ctx, e, ua)
	}
	dropped := func(n int) bool { return prev > 0 && float64(n) < float64(prev)*nodeDropRatio }

	var suggested uaChoice
	if explicit {
		suggested = m.advise(ctx, e, a, now, dropped(a.nodes()))
	} else if m.shouldProbe(a, haveCache, cached, now, dropped(a.nodes())) {
		a = m.probeBest(ctx, e, a, haveCache, cached, now)
	}

	n := a.nodes()
	drop := n > 0 && dropped(n)
	if n > 0 {
		m.mu.Lock()
		m.prevCount[e.Name] = n
		m.mu.Unlock()
	}
	return a, prev, drop, suggested
}

// shouldProbe decides whether an auto-UA entry compares all candidates this
// round. Never on 4xx (token/auth — no UA helps) or on a transport error
// (the next candidate would most likely time out the same way).
func (m *Manager) shouldProbe(a uaAttempt, haveCache bool, cached uaChoice, now time.Time, dropped bool) bool {
	if h := AsHTTPError(a.fetchErr); h != nil {
		return h.Status >= 500
	}
	if a.fetchErr != nil {
		return false
	}
	switch {
	case a.parseErr != nil, a.nodes() == 0, dropped:
		return true
	case !haveCache, now.Sub(cached.at) >= uaProbeTTL:
		return true
	}
	return false
}

// probeBest fetches with every candidate UA other than first.ua and returns
// the attempt with the most nodes. Ties keep the earlier attempt, so the UA
// already in use wins a tie and tags stay stable across rounds. The winner
// is cached; if every candidate came back empty the cache is cleared so the
// next round starts again from the global UA.
func (m *Manager) probeBest(ctx context.Context, e config.SubscriptionEntry, first uaAttempt, haveCache bool, cached uaChoice, now time.Time) uaAttempt {
	cands := uaCandidates(m.globalUA)
	if cands == nil {
		// Unrecognised vendor UA: don't swap it for a Clash one, but still
		// retry the global UA if a stale cache entry put us elsewhere.
		cands = []string{}
	}
	cands = append([]string{m.globalUA}, cands...)

	best := first
	tried := map[string]bool{strings.ToLower(first.ua): true}
	counts := []string{fmt.Sprintf("%s=%s", first.ua, primaryOutcome(first.fetchErr, first.parseErr, first.nodes()))}
	for _, ua := range cands {
		if tried[strings.ToLower(ua)] {
			continue
		}
		tried[strings.ToLower(ua)] = true
		a := m.attempt(ctx, e, ua)
		counts = append(counts, fmt.Sprintf("%s=%s", ua, primaryOutcome(a.fetchErr, a.parseErr, a.nodes())))
		if a.nodes() > best.nodes() {
			best = a
		}
	}

	m.mu.Lock()
	if best.nodes() > 0 {
		m.uaChoice[e.Name] = uaChoice{ua: best.ua, url: e.URL, at: now, nodes: best.nodes()}
	} else {
		delete(m.uaChoice, e.Name)
	}
	cb := m.onUADiscovered
	m.mu.Unlock()

	slog.Info("subscribe: ua probe", "name", e.Name, "selected", best.ua,
		"nodes", best.nodes(), "candidates", strings.Join(counts, ","))
	changed := !strings.EqualFold(best.ua, m.globalUA)
	if haveCache {
		changed = !strings.EqualFold(best.ua, cached.ua)
	}
	if best.nodes() > 0 && changed && cb != nil {
		cb(e.Name, best.ua)
	}
	return best
}

// advise probes alternatives for an entry with an explicit UserAgent and
// returns one that yields more nodes than the explicit UA did, or a zero
// uaChoice. Rate-limited to once per uaProbeTTL unless this round dropped.
// Skipped on 4xx and transport errors for the same reasons as shouldProbe.
func (m *Manager) advise(ctx context.Context, e config.SubscriptionEntry, a uaAttempt, now time.Time, dropped bool) uaChoice {
	if h := AsHTTPError(a.fetchErr); h != nil && h.Status < 500 {
		return uaChoice{}
	}
	if a.fetchErr != nil && AsHTTPError(a.fetchErr) == nil {
		return uaChoice{}
	}
	m.mu.RLock()
	adv, ok := m.uaAdvice[e.Name]
	m.mu.RUnlock()
	fresh := ok && adv.url == e.URL && now.Sub(adv.at) < uaProbeTTL
	if !fresh || dropped {
		adv = uaChoice{url: e.URL, at: now}
		for _, ua := range allUACandidates() {
			if strings.EqualFold(ua, e.UserAgent) {
				continue
			}
			if alt := m.attempt(ctx, e, ua); alt.nodes() > adv.nodes {
				adv.ua, adv.nodes = ua, alt.nodes()
			}
		}
		m.mu.Lock()
		m.uaAdvice[e.Name] = adv
		m.mu.Unlock()
		if adv.nodes > a.nodes() {
			slog.Info("subscribe: explicit ua is serving fewer nodes than an alternative",
				"name", e.Name, "explicit_ua", e.UserAgent, "explicit_nodes", a.nodes(),
				"suggested_ua", adv.ua, "suggested_nodes", adv.nodes)
		}
	}
	if adv.nodes > a.nodes() {
		return adv
	}
	return uaChoice{}
}

// typeCounts tallies outbounds by protocol type ("hysteria2": 33, ...). Lets
// an operator see at a glance that a subscription is missing a protocol.
func typeCounts(out []Outbound) map[string]int {
	if len(out) == 0 {
		return nil
	}
	c := map[string]int{}
	for _, o := range out {
		t, _ := o["type"].(string)
		if t == "" {
			t = "unknown"
		}
		c[t]++
	}
	return c
}

// DefaultUserAgent is the global subscribe UA when gateway.yaml sets none.
// It names the core the data plane actually runs, so providers that pick
// the served protocols by client capability serve us everything mihomo
// supports (hysteria2, tuic, anytls, vless-reality, ...). The old default,
// ClashforWindows, claims a Premium core that predates most of those.
const DefaultUserAgent = "mihomo/1.19.26"

// gatedUA is the legacy Clash Premium UA. Kept in the chain for the
// providers that only recognise it.
const gatedUA = "ClashforWindows/0.20.39"

// modernUACandidates is the full candidate chain, in tie-break order: when
// two UAs yield the same node count the earlier one wins. Newest-core claims
// first, because they unlock the most protocols; sing-box last, because
// Clash-family panels often answer it with nothing.
var modernUACandidates = []string{
	DefaultUserAgent,
	"clash-verge/v2.0.0",
	gatedUA,
	"sing-box/1.10.7",
}

// allUACandidates returns a copy of the full chain.
func allUACandidates() []string {
	return append([]string(nil), modernUACandidates...)
}

// uaCandidates returns the chain minus current. An unrecognised vendor UA
// (e.g. "Mozilla/5.0" set as the global UA) gets nil: it was chosen on
// purpose and must not be silently swapped for a Clash-family one.
func uaCandidates(current string) []string {
	lc := strings.ToLower(current)
	if lc != "" &&
		!strings.Contains(lc, "clash") &&
		!strings.Contains(lc, "stash") &&
		!strings.Contains(lc, "mihomo") &&
		!strings.Contains(lc, "sing-box") &&
		!strings.HasPrefix(lc, "turnout-gateway") {
		return nil
	}
	out := make([]string, 0, len(modernUACandidates))
	for _, ua := range modernUACandidates {
		if !strings.EqualFold(ua, current) {
			out = append(out, ua)
		}
	}
	return out
}

// primaryOutcome turns the (fetchErr, parseErr, nodeCount) of one attempt
// into a short string for the probe log line.
func primaryOutcome(fetchErr, parseErr error, n int) string {
	if h := AsHTTPError(fetchErr); h != nil {
		return fmt.Sprintf("http_%d", h.Status)
	}
	if fetchErr != nil {
		return "fetch_err"
	}
	if parseErr != nil {
		return "parse_err"
	}
	return fmt.Sprintf("%d", n)
}

func (m *Manager) Snapshot() ([]SubscriptionResult, time.Time) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastResults, m.lastRefreshed
}

// SetEntries swaps the subscription set the next Refresh will iterate. Used by
// the management API after CRUD edits — the underlying cfg.Subscriptions
// slice may have been reallocated, so we cannot rely on shared backing array.
func (m *Manager) SetEntries(entries []config.SubscriptionEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Defensive copy so external mutations to the caller's slice don't show
	// up mid-refresh.
	cp := make([]config.SubscriptionEntry, len(entries))
	copy(cp, entries)
	m.entries = cp
}

// ParseBytes runs the parse + filter + tag-prefix path on a body that the
// caller already has in memory — useful for offline replay (selftest), unit
// tests, and any path that doesn't go through the HTTP fetcher.
func ParseBytes(name, format string, body []byte) (SubscriptionResult, error) {
	res, _, err := parseBytesStats(name, format, body)
	return res, err
}

// parseBytesStats is ParseBytes plus the number of client-gating pseudo-nodes
// dropped by the filter. Refresh uses the count to report WHY a subscription
// yielded nothing, so the operator can tell an empty subscription from one
// that is refusing our client.
func parseBytesStats(name, format string, body []byte) (SubscriptionResult, int, error) {
	out, fmtName, err := parseAuto(body, format)
	if err != nil {
		return SubscriptionResult{}, 0, fmt.Errorf("parse %s: %w", name, err)
	}
	out, gated := filterOutboundsStats(out)
	for i := range out {
		tag := out[i].Tag()
		if tag == "" {
			tag = fmt.Sprintf("node-%d", i)
		}
		out[i]["tag"] = name + "/" + tag
	}
	return SubscriptionResult{Name: name, Format: fmtName, Outbounds: out}, gated, nil
}

// AllOutbounds returns a flat list of all outbounds from the last refresh,
// minus tags matching node_exclude_pattern.
func (m *Manager) AllOutbounds() []Outbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var all []Outbound
	for _, r := range m.lastResults {
		for _, o := range r.Outbounds {
			if m.exclude != nil && m.exclude.MatchString(o.Tag()) {
				continue
			}
			all = append(all, o)
		}
	}
	return all
}

// ExcludedTags returns the tags from the last refresh that
// node_exclude_pattern removes from AllOutbounds, in subscription order.
func (m *Manager) ExcludedTags() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.exclude == nil {
		return nil
	}
	var out []string
	for _, r := range m.lastResults {
		for _, o := range r.Outbounds {
			if t := o.Tag(); m.exclude.MatchString(t) {
				out = append(out, t)
			}
		}
	}
	return out
}

func parseAuto(body []byte, hint string) ([]Outbound, string, error) {
	switch hint {
	case "clash":
		o, err := parseClash(body)
		return o, "clash", err
	case "singbox":
		o, err := parseSingBox(body)
		return o, "singbox", err
	case "uri":
		o, err := parseURIList(body)
		return o, "uri", err
	case "sip008":
		o, err := parseSIP008(body)
		return o, "sip008", err
	}
	return detectAndParse(body)
}

func detectAndParse(body []byte) ([]Outbound, string, error) {
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) == 0 {
		return nil, "", errors.New("empty body")
	}
	// 1. JSON: sing-box (has "outbounds") or SIP008 (array of {server,...}).
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var probe any
		if err := json.Unmarshal([]byte(trimmed), &probe); err == nil {
			switch v := probe.(type) {
			case map[string]any:
				if _, ok := v["outbounds"]; ok {
					o, err := parseSingBox(body)
					return o, "singbox", err
				}
			case []any:
				o, err := parseSIP008(body)
				return o, "sip008", err
			}
		}
	}
	// 2. Clash YAML — looks for "proxies:" near the top.
	if strings.Contains(trimmed, "\nproxies:") || strings.HasPrefix(trimmed, "proxies:") {
		o, err := parseClash(body)
		return o, "clash", err
	}
	// 3. URI list — possibly base64-wrapped.
	if decoded, ok := tryBase64(trimmed); ok {
		trimmed = decoded
	}
	if hasURIScheme(trimmed) {
		o, err := parseURIList([]byte(trimmed))
		return o, "uri", err
	}
	return nil, "", errors.New("unknown subscription format")
}

func tryBase64(s string) (string, bool) {
	s = strings.TrimSpace(s)
	// Subscriptions typically use URL-safe base64 without padding.
	for _, dec := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := dec.DecodeString(s); err == nil {
			out := string(b)
			if hasURIScheme(out) {
				return out, true
			}
		}
	}
	return "", false
}

func hasURIScheme(s string) bool {
	for _, scheme := range []string{"vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://"} {
		if strings.Contains(s, scheme) {
			return true
		}
	}
	return false
}
