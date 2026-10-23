// rules.go — rules + rule-providers.
//
// mihomo natively reads sing-box .srs files (format: srs). turnout-gateway
// already manages those .srs files on disk under cfg.RuleSetsDir, so we
// reference them directly via type=file rule-providers — no second copy,
// same files sing-box would load.

package mihomo

import (
	"path/filepath"
	"strings"

	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

const (
	rsGeositeCN = "geosite-cn"
	rsGeoipCN   = "geoip-cn"
	// rsAdsAll is MetaCubeX's pure-advertising domain set. The tag doubles as
	// the provider key AND the on-disk filename (<tag>.mrs), so stage.sh must
	// save the fetched file under exactly this stem.
	rsAdsAll = "category-ads-all"
)

// poolRuleSets returns every rule-set tag claimed by any pool, deduped.
// Used by buildRuleProviders to ensure those tags get a provider even when
// they aren't in the whitelist (overseas mode, or whitelist that doesn't
// list them explicitly).
func (r *Renderer) poolRuleSets() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r.pools {
		for _, rs := range p.RuleSets {
			if !seen[rs] {
				seen[rs] = true
				out = append(out, rs)
			}
		}
	}
	return out
}

// buildRuleProviders emits `rule-providers:` — one provider per rule-set tag
// that the route table refers to. CN infra (geosite-cn / geoip-cn) always
// emitted; whitelist tags only emitted in whitelist mode; pool rule_sets
// always emitted (they route regardless of mode).
//
// Format: mihomo accepts `mrs` (its own binary format) — NOT sing-box's
// `srs`. MetaCubeX publishes both side by side; the .mrs file lives next
// to the .srs one with the same stem. We expect the deploy chain to fetch
// both into RuleSetsDir as <tag>.mrs.
func (r *Renderer) buildRuleProviders() map[string]any {
	dir := r.cfg.RuleSetsDir

	rp := map[string]any{
		rsGeositeCN: ruleProvider("domain", filepath.Join(dir, rsGeositeCN+".mrs")),
		rsGeoipCN:   ruleProvider("ipcidr", filepath.Join(dir, rsGeoipCN+".mrs")),
	}

	if r.cfg.Route.AdBlock {
		rp[rsAdsAll] = ruleProvider("domain", filepath.Join(dir, rsAdsAll+".mrs"))
	}

	if r.cfg.Route.Mode == "whitelist" {
		for _, tag := range r.cfg.Route.Whitelist.Geosites {
			rp[tag] = ruleProvider("domain", filepath.Join(dir, tag+".mrs"))
		}
		for _, tag := range r.cfg.Route.Whitelist.Geoips {
			rp[tag] = ruleProvider("ipcidr", filepath.Join(dir, tag+".mrs"))
		}
	}
	// Pool rule_sets — always present. behavior inferred from tag prefix
	// (geoip-* → ipcidr, everything else → domain).
	for _, tag := range r.poolRuleSets() {
		if _, ok := rp[tag]; ok {
			continue
		}
		behavior := "domain"
		if strings.HasPrefix(tag, "geoip-") {
			behavior = "ipcidr"
		}
		rp[tag] = ruleProvider(behavior, filepath.Join(dir, tag+".mrs"))
	}
	return rp
}

func ruleProvider(behavior, path string) map[string]any {
	return map[string]any{
		"type":     "file",
		"format":   "mrs",
		"behavior": behavior,
		"path":     path,
	}
}

// buildRules emits the `rules:` array. Order matters — first match wins.
//
// overseas mode (default):
//
//	IP-CIDR,LAN,DIRECT (no-resolve)
//	GEOIP/RULE-SET ip_is_private DIRECT
//	RULE-SET,geosite-cn,DIRECT
//	RULE-SET,geoip-cn,DIRECT,no-resolve
//	MATCH,out
//
// whitelist mode:
//
//	IP-CIDR,LAN,DIRECT (no-resolve)
//	RULE-SET,geosite-cn,DIRECT
//	RULE-SET,geoip-cn,DIRECT,no-resolve
//	[whitelisted geosite tags] → out
//	[whitelisted DOMAIN-SUFFIX] → out
//	[whitelisted geoip tags] → out (no-resolve)
//	[whitelisted IP-CIDR]   → out (no-resolve)
//	MATCH,DIRECT
//
// per-terminal mode (load_balance.per_terminal=true): domain-matched
// whitelist entries dispatch to the `perterm` sub-rule instead of `out`.
// perterm holds SRC-IP-CIDR,<terminal/32>,<node> slices (HRW-assigned over
// the us-pool members) + a MATCH,us-pool fallback — so one terminal's
// whitelisted traffic all exits one node. IP-based whitelist (geoip /
// ip_cidr, no-resolve) still goes to `out` (hardcoded-IP apps don't drift,
// and no-resolve doesn't translate into a SUB-RULE condition).
//
// Returns (rules, subRules). subRules is empty unless per-terminal is on.
func (r *Renderer) buildRules(outbounds []subscribe.Outbound) ([]string, map[string]any) {
	var rules []string
	subRules := map[string]any{}

	// Private/LAN — no DNS resolution needed.
	rules = append(rules,
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
		"IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
		"IP-CIDR,224.0.0.0/4,DIRECT,no-resolve",
	)

	// Ad blocking must precede the CN-direct line below: rules are first-match,
	// so a CN-hosted ad domain would otherwise hit geosite-cn and be forwarded
	// instead of rejected.
	if r.cfg.Route.AdBlock {
		rules = append(rules, "RULE-SET,"+rsAdsAll+",REJECT")
	}

	// CN direct — must come before whitelist hits so CN endpoints of
	// global services (e.g. apple.com.cn) don't get routed via airport.
	rules = append(rules,
		"RULE-SET,"+rsGeositeCN+",DIRECT",
		"RULE-SET,"+rsGeoipCN+",DIRECT,no-resolve",
	)

	// Per-terminal: build the perterm sub-rule once. domainTarget below
	// dispatches domain whitelist hits into it. Each rule routes the
	// terminal to its dedicated fb-<ip> fallback group, which mihomo's
	// fallback type backs with [primary, secondary] from the routing pool.
	// One terminal → one egress at any given time, with automatic primary
	// → secondary failover when the primary fails mihomo's url-test.
	perterm := r.perTerminal && r.node.ClientSubnet != ""
	if perterm {
		slices := r.perTerminalSlices(outbounds)
		if len(slices) == 0 {
			// No routing members — disable perterm this render rather
			// than emit a sub-rule that dead-ends.
			perterm = false
		} else {
			subRules["perterm"] = slices
		}
	}

	// domainRule routes a domain-matching condition to either the perterm
	// sub-rule (per-terminal) or the `out` selector (default).
	domainRule := func(cond string) string {
		if perterm {
			return "SUB-RULE,(" + cond + "),perterm"
		}
		return cond + "," + outSelector
	}

	// ipRule is domainRule for IP-keyed conditions. no-resolve must survive
	// inside the SUB-RULE condition — verified against mihomo v1.19.26 on the
	// node (`mihomo -t` accepts "SUB-RULE,(RULE-SET,geoip-x,no-resolve),perterm").
	//
	// These used to go straight to `out` even with per-terminal on. `out`
	// leads with us-pool, a consistent-hashing load-balancer keyed on the
	// DESTINATION, so one terminal's IP-matched flows (QUIC to Google IPs,
	// Telegram MTProto) were spread across every egress while its
	// domain-matched flows stayed pinned — exactly the multi-IP pattern
	// per-terminal exists to prevent.
	ipRule := func(cond string) string {
		if perterm {
			return "SUB-RULE,(" + cond + ",no-resolve),perterm"
		}
		return cond + "," + outSelector + ",no-resolve"
	}

	// Pool routing. Class pools (node_pattern / size / per_terminal /
	// domain_suffix) own their dispatch: per-terminal pools get a
	// perterm-<pool> sub-rule over their own members, shared pools are
	// targeted directly. Legacy pools keep the original behavior: with
	// global per-term on they route through the unified `perterm` (one
	// terminal, one IP across all classes); otherwise they target the
	// named load-balance group.
	//
	// Emitted before the whitelist so a class can claim a specific domain
	// (e.g. Gemini inside geosite-google) ahead of a broader tag.
	poolRouted := map[string]bool{}
	var classTags, classUsPool []string
	classResolved := false
	resolveClassMembers := func() {
		if classResolved {
			return
		}
		classTags = nodeTags(outbounds)
		classUsPool = r.usPoolMembers(outbounds)
		classResolved = true
	}
	for _, p := range r.pools {
		if p.IsClassPool() {
			resolveClassMembers()
			members := r.poolDispatchMembers(p, classTags, classUsPool)
			classPerTerm := p.PerTerminalEnabled() &&
				r.node.ClientSubnet != "" &&
				len(members) >= perTerminalFallbackDepth
			subName := "perterm-" + p.Name
			if classPerTerm {
				if slices := r.perTerminalSlicesFor(members, poolGroupPrefix(p.Name), p.Name); len(slices) > 0 {
					subRules[subName] = slices
				} else {
					classPerTerm = false
				}
			}
			for _, d := range p.DomainSuffix {
				if classPerTerm {
					rules = append(rules, "SUB-RULE,(DOMAIN-SUFFIX,"+d+"),"+subName)
				} else {
					rules = append(rules, "DOMAIN-SUFFIX,"+d+","+p.Name)
				}
			}
			for _, tag := range p.RuleSets {
				if poolRouted[tag] {
					continue
				}
				noResolve := ""
				if strings.HasPrefix(tag, "geoip-") {
					noResolve = ",no-resolve"
				}
				if classPerTerm {
					rules = append(rules, "SUB-RULE,(RULE-SET,"+tag+noResolve+"),"+subName)
				} else {
					rules = append(rules, "RULE-SET,"+tag+","+p.Name+noResolve)
				}
				poolRouted[tag] = true
			}
			continue
		}
		// Legacy pool (probe-gated subset of us-pool).
		for _, tag := range p.RuleSets {
			if poolRouted[tag] {
				continue
			}
			if perterm {
				if strings.HasPrefix(tag, "geoip-") {
					rules = append(rules, ipRule("RULE-SET,"+tag))
				} else {
					rules = append(rules, domainRule("RULE-SET,"+tag))
				}
			} else {
				noResolve := ""
				if strings.HasPrefix(tag, "geoip-") {
					noResolve = ",no-resolve"
				}
				rules = append(rules, "RULE-SET,"+tag+","+p.Name+noResolve)
			}
			poolRouted[tag] = true
		}
	}

	if r.cfg.Route.Mode == "whitelist" {
		for _, tag := range r.cfg.Route.Whitelist.Geosites {
			if poolRouted[tag] {
				continue
			}
			rules = append(rules, domainRule("RULE-SET,"+tag))
		}
		for _, sx := range r.cfg.Route.Whitelist.DomainSuffix {
			rules = append(rules, domainRule("DOMAIN-SUFFIX,"+sx))
		}
		// IP-based whitelist (no-resolve; hardcoded-IP apps like Telegram
		// MTProto). Pinned per terminal like everything else — see ipRule.
		for _, tag := range r.cfg.Route.Whitelist.Geoips {
			if poolRouted[tag] {
				continue
			}
			rules = append(rules, ipRule("RULE-SET,"+tag))
		}
		for _, cidr := range r.cfg.Route.Whitelist.IPCIDR {
			rules = append(rules, ipRule("IP-CIDR,"+cidr))
		}
		rules = append(rules, "MATCH,DIRECT")
	} else {
		// overseas mode: everything non-CN goes overseas. Per-terminal
		// dispatches the catch-all through perterm; else straight to out.
		if perterm {
			rules = append(rules, "SUB-RULE,(MATCH),perterm")
		} else {
			rules = append(rules, "MATCH,"+outSelector)
		}
	}

	return rules, subRules
}
