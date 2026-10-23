// perterminal.go — "one terminal, one egress, with automatic failover".
//
// Each terminal IP is assigned two members in HRW order: [primary,
// secondary]. SRC-IP-CIDR / SRC-IP-SUFFIX rules in the perterm sub-rule
// route the terminal to a `fallback` proxy-group that holds exactly that
// pair. mihomo's fallback type tries members in order and uses the first
// one whose alive bit is true — so when primary dies, traffic auto-routes
// to secondary within mihomo's url-test interval, no turnout-gateway
// intervention.
//
// Groups are keyed by the PAIR, not by the terminal. This matters at
// scale: a /16 in suffix mode has 1024 terminal units but only K(K-1)
// distinct ordered pairs (56 for an 8-member routing pool; both orders of
// a node pair occur, and order is semantic — it selects the primary).
// Emitting one group per unit meant ~2k fallback groups per deployment,
// and mihomo starts a health check for EVERY group the moment the config
// is applied (provider/healthcheck.go: the `go hc.check()` in process() is
// unconditional; `lazy` only skips later ticks). One PUT /configs then
// fired ~4k concurrent dials at 8 nodes — each node sat in 250-500
// groups — and took 6.1-7.5s. Measured on 10.100.6.15 (2026-10-23):
// identical config with the per-unit groups removed reloads in 0.48s and
// uses 215MB instead of 665MB RSS.
//
// Pair-keyed groups are semantically identical: mihomo's alive bit lives
// on the shared proxy object, not on the group, so N groups containing the
// same node see the same liveness. Deduplicating them only removes
// duplicate health checks.
//
// Why not bare-node SRC-IP-CIDR (the previous design): SRC-IP-CIDR is a
// hard route — when its target proxy is alive=false, mihomo just fails
// the connection (no fallback). Per-terminal fallback groups give us
// mihomo's native alive-bit failover while preserving the per-terminal
// stable identity (the same pair group → the same primary by default; only
// when primary is down does the egress IP change).
//
// HRW (rendezvous hashing) properties carry over: when the routing pool
// gains/loses a member, only the terminals whose top-2 changed get
// reassigned — most terminals keep their (primary, secondary) pair stable.
//
// Large subnets: the unit of assignment is a host when the subnet has at
// most maxPerTerminalUnits hosts. Above that it is a SUFFIX BUCKET: the
// terminal's low suffixBits address bits (10 → 1024 buckets), matched with
// mihomo's SRC-IP-SUFFIX. Every terminal in a bucket shares its
// [primary, secondary]; a terminal still never spreads across egresses.
//
// Why low bits and not contiguous blocks: a /26 block put 64 ADJACENT
// addresses on one egress pair, and adjacent addresses are usually one
// floor or one team — they all landed on the same node and all failed
// over together. Low-bit buckets give neighbours (…101.126, …101.127)
// different buckets and independent HRW draws, so a team spreads across
// the pool the way per-host assignment would. Bucket members are 1024
// addresses apart (192.168.0.5, 192.168.4.5, …).
//
// History: before buckets, any subnet over 1024 hosts silently got NO
// per-terminal pinning (2026-10-22: one terminal on four egresses at once);
// contiguous /26 blocks fixed that and were replaced the same day for the
// clustering above.

package mihomo

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"sort"

	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

const (
	// maxPerTerminalUnits caps the number of per-terminal RULE units, and
	// therefore the maximum number of fallback groups (one group per
	// distinct pair, at most one per unit). Subnets with more hosts than
	// this are bucketed by address suffix instead (see perTerminalUnits),
	// so the config stays bounded (/16 would otherwise be 65k rules)
	// without dropping pinning. In steady state groups are far fewer:
	// K(K-1) ordered pairs for the routing pool (56 for 8 nodes), not 1024.
	maxPerTerminalUnits = 1024

	// suffixBits is log2(maxPerTerminalUnits): the low address bits that
	// select a bucket in suffix mode.
	suffixBits = 10

	// perTerminalFallbackDepth is the number of HRW-ordered members
	// included in each fallback group. 2 = [primary, secondary] is the
	// minimum useful redundancy; larger values trade per-flap rotation
	// count for breadth (more candidates means more potential IP changes
	// during a multi-node failure).
	perTerminalFallbackDepth = 2

	// perTerminalGroupPrefix is the proxy-group naming convention. Operators
	// + the /api/pool/terminal endpoint rely on this prefix to enumerate
	// and look up terminal-specific groups.
	perTerminalGroupPrefix = "fb-"

	// pairGroupInfix separates pair-keyed group names (fb-p-<hash>) from
	// the pre-2026-10-23 per-terminal-unit names (fb-<ip> / fb-s<bucket>).
	// A distinct infix makes a stale bookmark/log line obviously stale
	// instead of silently referring to a different terminal's group.
	pairGroupInfix = "p-"
)

// pairGroupSuffix returns the deterministic group-name suffix for an
// HRW-ordered member list, or "" when there are fewer than
// perTerminalFallbackDepth members (callers then emit no group at all).
//
// The hash covers the ordered pair, so [A,B] and [B,A] are different
// groups — fallback order is semantic (primary first), not a set. Names
// must stay stable across renders: a name change has no effect on routing
// but makes operator-facing diffing noise, and the API derives the same
// name from the same pair.
func pairGroupSuffix(members []string) string {
	if len(members) < perTerminalFallbackDepth {
		return ""
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(members[0]))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(members[1]))
	return fmt.Sprintf("%s%012x", pairGroupInfix, splitmix64(h.Sum64())&0xffffffffffff)
}

// perTerminalMembers returns the routing-member pool used for per-terminal
// HRW assignment. Both perTerminalSlices and perTerminalFallbackGroups must
// call this so they always operate on the same set — if they diverge, rules
// can reference pair groups that were never emitted (or vice versa),
// causing mihomo to reject the config with "proxy not found".
func (r *Renderer) perTerminalMembers(outbounds []subscribe.Outbound) []string {
	members := r.intersectWithPresent(r.routingMembers, outbounds)
	if len(members) == 0 {
		members = r.defaultPoolMembers(outbounds)
	}
	return members
}

// perTerminalSlices returns the `perterm` sub-rule body. Every unit in the
// client subnet maps to the fallback group that carries its HRW pair, and
// the MATCH fallback at the end catches sources outside the subnet.
//
// Returns nil when there are no candidate routing members (validate path
// with empty outbounds, or unconfigured perTerminal); the caller then
// falls back to a single default-pool MATCH rule.
func (r *Renderer) perTerminalSlices(outbounds []subscribe.Outbound) []string {
	return r.perTerminalSlicesFor(r.perTerminalMembers(outbounds), perTerminalGroupPrefix, defaultPool)
}

// perTerminalSlicesFor is the generalized body of a per-term sub-rule: one
// SRC-IP rule per terminal unit pointing at the pair group its HRW
// assignment resolves to, then a fallback for sources outside
// client_subnet. Used by the default class (prefix "fb-", fallback
// default-pool) and by class pools (prefix "fb-<pool>-", fallback <pool>).
//
// One rule per UNIT (up to 1024), but only one GROUP per distinct
// [primary, secondary] pair — many units share a pair and therefore share
// a group. Rules are cheap; health-checked groups are not.
func (r *Renderer) perTerminalSlicesFor(members []string, groupPrefix, fallbackGroup string) []string {
	// Need at least perTerminalFallbackDepth members to form a useful
	// fallback chain. Callers check the same condition before emitting the
	// SRC-IP rules, so the two never diverge.
	if len(members) < perTerminalFallbackDepth {
		return nil
	}
	units := perTerminalUnits(r.node.ClientSubnet)
	if len(units) == 0 {
		return nil
	}
	rules := make([]string, 0, len(units)+1)
	for _, u := range units {
		suffix := pairGroupSuffix(hrwTopN(u.key, members, perTerminalFallbackDepth))
		rules = append(rules, fmt.Sprintf("%s,%s,%s%s", u.ruleType, u.match, groupPrefix, suffix))
	}
	rules = append(rules, "MATCH,"+fallbackGroup)
	return rules
}

// perTerminalFallbackGroups returns the fallback proxy-group definitions
// for every distinct [primary, secondary] pair drawn from the routing
// pool. Returns nil when the pool is empty or the subnet can't be
// enumerated.
//
// The probe URL + interval mirror url_test config so all groups share
// the same liveness signal. lazy=true means the group only probes when
// it has active flows — keeps probe traffic proportional to actual
// terminal activity rather than the static subnet size. Note that mihomo
// still runs one check at group creation (see the package comment), which
// is exactly why the group count must stay bounded by K(K-1) ordered
// pairs.
func (r *Renderer) perTerminalFallbackGroups(outbounds []subscribe.Outbound, probeURL string, intervalSec int) []map[string]any {
	return r.perTerminalFallbackGroupsFor(r.perTerminalMembers(outbounds), perTerminalGroupPrefix, probeURL, intervalSec)
}

// perTerminalFallbackGroupsFor emits one fallback group per distinct
// [primary, secondary] pair named groupPrefix+p-<hash>, each containing
// its two members in HRW order. Shared by the default class and class
// pools so their failover semantics stay identical.
func (r *Renderer) perTerminalFallbackGroupsFor(members []string, groupPrefix, probeURL string, intervalSec int) []map[string]any {
	if len(members) < perTerminalFallbackDepth {
		// Need at least perTerminalFallbackDepth members to form a useful
		// fallback chain. perTerminalSlicesFor checks the same condition, so
		// when this returns nil no SRC-IP rules referencing these groups
		// will have been emitted either.
		return nil
	}
	units := perTerminalUnits(r.node.ClientSubnet)
	if len(units) == 0 {
		return nil
	}
	// Upper bound is K(K-1) ordered pairs; starting at the unit count would
	// allocate 1024 entries for ~56 groups. K is small by design
	// (pool_sizing), but fall back to the unit count if members is
	// unexpectedly huge.
	capacity := len(members) * (len(members) - 1)
	if capacity > len(units) {
		capacity = len(units)
	}
	out := make([]map[string]any, 0, capacity)
	seen := make(map[string]bool, capacity)
	for _, u := range units {
		ranked := hrwTopN(u.key, members, perTerminalFallbackDepth)
		suffix := pairGroupSuffix(ranked)
		if suffix == "" || seen[suffix] {
			continue
		}
		seen[suffix] = true
		out = append(out, map[string]any{
			"name":     groupPrefix + suffix,
			"type":     "fallback",
			"proxies":  ranked,
			"url":      probeURL,
			"interval": intervalSec,
			"lazy":     true,
		})
	}
	return out
}

// AssignmentForIP returns the HRW-ordered routing members for one
// terminal IP. Returns ([primary, secondary, ...], true) when the IP is
// inside the configured client_subnet AND the routing pool is non-empty,
// or (nil, false) when not applicable.
//
// Used by the /api/pool/terminal endpoint to surface "which node carries
// this terminal's traffic" without requiring the caller to re-implement
// HRW or read mihomo's runtime state.
//
// Reads routingMembers under stateMu so the API can see post-hot-reload
// pool composition. Without the lock the API lags by however long it
// takes a sub refresh to propagate (which can be never if no sub
// refresh fires after a scorer hot-reload).
func (r *Renderer) AssignmentForIP(ip string, outbounds []subscribe.Outbound) ([]string, bool) {
	r.stateMu.RLock()
	routingSnapshot := append([]string(nil), r.routingMembers...)
	r.stateMu.RUnlock()
	members := r.intersectWithPresent(routingSnapshot, outbounds)
	if len(members) == 0 {
		members = r.defaultPoolMembers(outbounds)
	}
	if len(members) == 0 {
		return nil, false
	}
	if !ipInSubnet(ip, r.node.ClientSubnet) {
		return nil, false
	}
	depth := perTerminalFallbackDepth
	if depth > len(members) {
		depth = len(members)
	}
	return hrwTopN(perTerminalKey(ip, r.node.ClientSubnet), members, depth), true
}

// PerTerminalGroupName is the fb-* proxy-group that carries traffic from
// ip under the given client_subnet, or "" when ip is outside it or the
// assignment has fewer than two members (no group is rendered then).
//
// assigned is the HRW-ordered result from AssignmentForIP; the group is
// keyed by its first two entries, matching perTerminalFallbackGroupsFor.
// Exported so the API reports the same name the renderer emits — they must
// agree, and both derive it from pairGroupSuffix.
func PerTerminalGroupName(ip, clientSubnet string, assigned []string) string {
	if !ipInSubnet(ip, clientSubnet) {
		return ""
	}
	if perTerminalKey(ip, clientSubnet) == "" {
		return ""
	}
	if s := pairGroupSuffix(assigned); s != "" {
		return perTerminalGroupPrefix + s
	}
	return ""
}

// poolGroupPrefix is the proxy-group prefix for a class pool's per-terminal
// groups. The full pool name is used (ai-pool → "fb-ai-pool-") so it can
// never collide with the default "fb-" prefix or another pool's name.
func poolGroupPrefix(pool string) string {
	return perTerminalGroupPrefix + pool + "-"
}

// PoolPerTerminalGroupName is the fb-<pool>-* group for a class pool, or ""
// when the terminal is outside client_subnet or the pool assignment has
// fewer than two members. Mirrors PerTerminalGroupName for named pools; the
// API uses it so its report matches the renderer.
func PoolPerTerminalGroupName(pool, ip, clientSubnet string, assigned []string) string {
	if !ipInSubnet(ip, clientSubnet) {
		return ""
	}
	if perTerminalKey(ip, clientSubnet) == "" {
		return ""
	}
	if s := pairGroupSuffix(assigned); s != "" {
		return poolGroupPrefix(pool) + s
	}
	return ""
}

// PoolAssignmentForIP returns the HRW-ordered members for one terminal IP
// within a named class pool. Returns (nil, false) when the pool has no
// rendered members or the IP is outside client_subnet.
//
// Reads poolMembers under stateMu: the scorer publishes it on every
// hot-reload, and the API must see the same list the renderer emitted.
func (r *Renderer) PoolAssignmentForIP(ip, pool string, outbounds []subscribe.Outbound) ([]string, bool) {
	r.stateMu.RLock()
	wanted := append([]string(nil), r.poolMembers[pool]...)
	r.stateMu.RUnlock()
	members := r.intersectWithPresent(wanted, outbounds)
	if len(members) == 0 {
		return nil, false
	}
	if !ipInSubnet(ip, r.node.ClientSubnet) {
		return nil, false
	}
	depth := perTerminalFallbackDepth
	if depth > len(members) {
		depth = len(members)
	}
	return hrwTopN(perTerminalKey(ip, r.node.ClientSubnet), members, depth), true
}

// ptUnit is one per-terminal routing unit: the rule that matches its
// terminals and the key that names its group and seeds HRW.
type ptUnit struct {
	ruleType string // "SRC-IP-CIDR" (host) or "SRC-IP-SUFFIX" (bucket)
	match    string // "10.1.3.7/32"  or "0.0.1.126/10"
	key      string // "10.1.3.7"     or "s0.0.1.126" (group fb-s0.0.1.126)
}

// suffixMode reports whether cidr is too large for per-host units.
// ok=false for non-IPv4 or unparsable input.
func suffixMode(cidr string) (suffix, ok bool) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return false, false // IPv6 client pools not supported
	}
	ones, _ := ipnet.Mask.Size()
	hostBits := 32 - ones
	hosts := 1 << uint(hostBits)
	if hostBits >= 2 {
		hosts -= 2 // network + broadcast, as enumerateHosts counts
	}
	return hosts > maxPerTerminalUnits, true
}

// suffixAddr renders bucket n as the dotted address whose low suffixBits
// equal n — the form SRC-IP-SUFFIX takes ("0.0.1.126" for n=382).
func suffixAddr(n uint32) string {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return net.IP(b[:]).String()
}

// perTerminalUnits lists every routing unit in cidr (see ptUnit).
func perTerminalUnits(cidr string) []ptUnit {
	suffix, ok := suffixMode(cidr)
	if !ok {
		return nil
	}
	if !suffix {
		hosts := enumerateHosts(cidr, maxPerTerminalUnits)
		out := make([]ptUnit, 0, len(hosts))
		for _, h := range hosts {
			out = append(out, ptUnit{ruleType: "SRC-IP-CIDR", match: h + "/32", key: h})
		}
		return out
	}
	n := 1 << suffixBits
	out := make([]ptUnit, 0, n)
	for i := 0; i < n; i++ {
		a := suffixAddr(uint32(i))
		out = append(out, ptUnit{
			ruleType: "SRC-IP-SUFFIX",
			match:    fmt.Sprintf("%s/%d", a, suffixBits),
			key:      "s" + a,
		})
	}
	return out
}

// perTerminalKey maps one terminal ip to its unit key: the ip itself in
// host mode, "s<suffix>" in suffix mode. "" if not computable. Callers
// check subnet membership separately.
func perTerminalKey(ip, cidr string) string {
	suffix, ok := suffixMode(cidr)
	if !ok {
		return ""
	}
	if !suffix {
		return ip
	}
	p := net.ParseIP(ip).To4()
	if p == nil {
		return ""
	}
	return "s" + suffixAddr(binary.BigEndian.Uint32(p)&(1<<suffixBits-1))
}

// intersectWithPresent filters wanted by membership in outbounds' tag set.
// Returns nil if outbounds is empty (validate path) so callers can fall
// back to their default member source. nil-safe on wanted.
func (r *Renderer) intersectWithPresent(wanted []string, outbounds []subscribe.Outbound) []string {
	if len(wanted) == 0 || len(outbounds) == 0 {
		return nil
	}
	present := make(map[string]bool, len(outbounds))
	for _, o := range outbounds {
		if t := o.Tag(); t != "" {
			present[t] = true
		}
	}
	out := make([]string, 0, len(wanted))
	for _, w := range wanted {
		if present[w] {
			out = append(out, w)
		}
	}
	return out
}

// enumerateHosts returns the usable host IPs of a CIDR (excludes network +
// broadcast for IPv4 prefixes shorter than /31). Returns nil for non-CIDR
// or when the host count exceeds limit.
func enumerateHosts(cidr string, limit int) []string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	ip4 := ipnet.IP.To4()
	if ip4 == nil {
		return nil // IPv6 client pools not supported for per-terminal slicing
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return nil
	}
	count := 1 << uint(hostBits)
	base := binary.BigEndian.Uint32(ip4)
	var out []string
	for i := 0; i < count; i++ {
		if hostBits >= 2 && (i == 0 || i == count-1) {
			continue
		}
		if len(out) >= limit {
			return nil
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+uint32(i))
		out = append(out, net.IP(b[:]).String())
	}
	return out
}

// ipInSubnet returns true when ip is inside cidr.
func ipInSubnet(ip, cidr string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipnet.Contains(parsed)
}

// splitmix64 is the finalizer applied to the FNV output in hrwTopN.
//
// FNV-1a has weak avalanche: it is a multiply-xor over bytes with no
// final mixing step, so structured inputs leave visible correlation in
// the high bits that decide the HRW argmax. Measured on 92's live
// 8-member routing pool over the whole 254-terminal /24, member[0] came
// out as [5 9 17 17 23 59 62 62] — a 12.4x spread between the least and
// most loaded egress, chi2=136 against uniform.
//
// This is NOT about the CJK/emoji node names, which was the initial
// suspicion. An ASCII control set (n1..n8) skewed 11.2x with one node
// taking 52.8% of terminals, i.e. worse. The skew depends
// unpredictably on the particular name set.
//
// splitmix64's finalizer fixes it: the same measurement becomes
// [22 26 31 32 34 35 36 38], 1.7x, chi2=6.3. It also removes the
// "K=3 needs a lucky triple" problem — across all 56 three-member
// subsets of that pool, subsets putting >=45% of terminals on one node
// drop from 40/56 to 0/56, and the worst-case single-node share drops
// from 52.0% to 40.6%.
//
// Rejected alternative: hashing member-then-ip instead of ip-then-member.
// It is dramatically worse, not better — 74.8% of terminals landed on a
// single node (chi2=981), because the trailing ip bytes are nearly
// identical across a /24 and FNV's tail dominates the result.
func splitmix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// hrwTopN returns the top-N members for an IP in HRW score order
// (highest score first = primary). Deterministic; the same (ip, members)
// always produces the same ordering. Adding/removing one member only
// reshuffles entries containing that member; others stay stable.
//
// NOTE: changing the hash changes every terminal's assignment exactly
// once. The splitmix64 finalizer was added 2026-08-12 and reshuffled all
// 254 terminals in one step; that is a one-time cost, not a recurring
// one, and the HRW stability property above is unaffected.
func hrwTopN(ip string, members []string, n int) []string {
	if n <= 0 || len(members) == 0 {
		return nil
	}
	type scored struct {
		name  string
		score uint64
	}
	scoredMembers := make([]scored, len(members))
	for i, m := range members {
		h := fnv.New64a()
		_, _ = h.Write([]byte(ip))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(m))
		scoredMembers[i] = scored{m, splitmix64(h.Sum64())}
	}
	sort.Slice(scoredMembers, func(i, j int) bool {
		return scoredMembers[i].score > scoredMembers[j].score
	})
	if n > len(scoredMembers) {
		n = len(scoredMembers)
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = scoredMembers[i].name
	}
	return out
}

// hrwPick is preserved as a thin wrapper over hrwTopN(..., 1) for any
// existing call site (e.g. tests). Same behavior as before — first HRW.
func hrwPick(ip string, members []string) string {
	r := hrwTopN(ip, members, 1)
	if len(r) == 0 {
		return ""
	}
	return r[0]
}
