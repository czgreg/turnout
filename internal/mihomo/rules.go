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

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

const (
	rsGeositeCN = "geosite-cn"
	rsGeoipCN   = "geoip-cn"
	// The three ad rule-sets. rsAdsAll is MetaCubeX's category-ads-all: the
	// superset (903 domains), not the narrower category-ads (843) — the 60
	// extra entries are where the mainstream ad exchanges live (adnxs,
	// casalemedia, openx, pubmatic, taboola, mgid). The same 60 also carry
	// tracker/dev domains (+.sentry.io, +.segment.io, +.clearbit.com); with no
	// per-domain exemption that is the accepted cost of the switch.
	rsAdsAll = "category-ads-all"
	// rsAntiAD is the CN-oriented anti-AD list (~112k domains). It is plain
	// text, one domain per line — no .mrs conversion needed.
	rsAntiAD = "anti-ad"
	// rsCNAMEAds is AdGuard's cname-trackers "disguised" list (~11.7k): the
	// first-party-looking domains that CNAME to ad/tracking servers. Blocking
	// these is the only way a domain-level rule reaches CNAME-cloaked ads.
	rsCNAMEAds = "cname-ads"
	// Adult-content sets. rsPorn ships as .mrs (compiled `+.domain`), rsNSFW
	// as normalized plain text (`+.domain` per line); see AdultRuleSets.
	rsPorn = "category-porn"
	rsNSFW = "nsfw"
)

// RuleSetSpec describes one file ad blocking depends on.
type RuleSetSpec struct {
	Tag    string // provider key, also the RULE-SET argument
	File   string // basename under RuleSetsDir
	Format string // mihomo rule-provider format: "mrs" or "text"
}

// AdRuleSets is the single source of truth for ad blocking: the renderer emits
// one REJECT line per entry, and the API refuses to switch it on unless every
// File is on disk. Order is cosmetic (fixed so rendered diffs stay stable) —
// all of them must precede geosite-cn.
var AdRuleSets = []RuleSetSpec{
	{Tag: rsAdsAll, File: rsAdsAll + ".mrs", Format: "mrs"},
	{Tag: rsAntiAD, File: rsAntiAD + ".txt", Format: "text"},
	{Tag: rsCNAMEAds, File: rsCNAMEAds + ".txt", Format: "text"},
}

// Adult-content rule-sets. rsPorn is MetaCubeX's category-porn, whose .mrs
// entries are compiled as `+.domain` — apex AND all subdomains. rsNSFW is
// HaGeZi's NSFW list; its upstream form is one BARE domain per line, which
// mihomo would match exactly, so stage.sh rewrites each line to `+.domain`
// before it reaches the node. A bare entry only ever matches its own host:
// verified against mihomo v1.19.26 (bare `x.invalid` did not match
// `www.x.invalid`; `+.x.invalid` did).
var AdultRuleSets = []RuleSetSpec{
	{Tag: rsPorn, File: rsPorn + ".mrs", Format: "mrs"},
	{Tag: rsNSFW, File: rsNSFW + ".txt", Format: "text"},
}

// quicRejectRule rejects QUIC (UDP 443). It heads every sub-rule, whose
// traffic is all proxied, and guardQUIC builds the conditional form for rules
// that target a proxy group directly.
//
// Why: the airport carries UDP inside its TCP tunnel (hutao is anytls), and
// QUIC's own congestion control on top of that collapses. Measured on
// 10.100.6.15 (2026-10-29): a terminal's YouTube video flow over QUIC held
// 0.4-1.2 Mbps for 30s straight through hutao/日本_BGP_A, while TCP through
// the same node and terminal ran at 83-89 Mbps. 1080p needs ~5 Mbps.
// Browsers treat a dead QUIC path as "use TCP", so rejecting is enough.
const quicRejectRule = "AND,((NETWORK,UDP),(DST-PORT,443)),REJECT"

// guardQUIC returns the rule that rejects QUIC matching cond. Emit it
// immediately before the proxied rule with the same cond. opts carries the
// rule's trailing options (",no-resolve" or ""); mihomo parses them inside a
// logic sub-condition the same way as inside a SUB-RULE one.
func guardQUIC(cond, opts string) string {
	return "AND,((NETWORK,UDP),(DST-PORT,443),(" + cond + opts + ")),REJECT"
}

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

// poolRuleLists returns every external classical list claimed by any pool,
// deduped by tag. config.validatePools already rejects duplicate tags; the
// dedupe here keeps the renderer safe for configs assembled in tests.
func (r *Renderer) poolRuleLists() []config.RuleListConfig {
	seen := map[string]bool{}
	var out []config.RuleListConfig
	for _, p := range r.pools {
		for _, rl := range p.RuleLists {
			if !seen[rl.Tag] {
				seen[rl.Tag] = true
				out = append(out, rl)
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
		rsGeositeCN: ruleProvider("domain", "mrs", filepath.Join(dir, rsGeositeCN+".mrs")),
		rsGeoipCN:   ruleProvider("ipcidr", "mrs", filepath.Join(dir, rsGeoipCN+".mrs")),
	}

	// Ad blocking ships as three sets: mrs for the MetaCubeX one, plain text
	// for the two community lists (no conversion step, so stage.sh can fetch
	// them verbatim).
	if r.cfg.Route.AdBlock {
		for _, rs := range AdRuleSets {
			rp[rs.Tag] = ruleProvider("domain", rs.Format, filepath.Join(dir, rs.File))
		}
	}

	// Adult-content blocking — same shape as AdBlock. The .mrs is precompiled
	// with `+.` entries; the text list is normalized by stage.sh.
	if r.cfg.Route.AdultBlock {
		for _, rs := range AdultRuleSets {
			rp[rs.Tag] = ruleProvider("domain", rs.Format, filepath.Join(dir, rs.File))
		}
	}

	if r.cfg.Route.Mode == "whitelist" {
		for _, tag := range r.cfg.Route.Whitelist.Geosites {
			rp[tag] = ruleProvider("domain", "mrs", filepath.Join(dir, tag+".mrs"))
		}
		for _, tag := range r.cfg.Route.Whitelist.Geoips {
			rp[tag] = ruleProvider("ipcidr", "mrs", filepath.Join(dir, tag+".mrs"))
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
		rp[tag] = ruleProvider(behavior, "mrs", filepath.Join(dir, tag+".mrs"))
	}
	// Pool rule_lists — operator-supplied classical lists (one full rule per
	// line, e.g. the vendor Gemini.list). `classical` + `text` is what keeps
	// DOMAIN-KEYWORD lines meaningful; a `domain` provider would read them as
	// literal hostnames and silently match nothing.
	for _, rl := range r.poolRuleLists() {
		if _, ok := rp[rl.Tag]; ok {
			continue
		}
		rp[rl.Tag] = ruleProviderClassical(filepath.Join(dir, rl.Tag+".list"))
	}
	return rp
}

func ruleProvider(behavior, format, path string) map[string]any {
	return map[string]any{
		"type":     "file",
		"format":   format,
		"behavior": behavior,
		"path":     path,
	}
}

// ruleProviderClassical declares a text rule list whose lines are complete
// rules ("DOMAIN-SUFFIX,x", "DOMAIN-KEYWORD,y", ...). mihomo parses each text
// line with the normal rule parser for this behavior.
func ruleProviderClassical(path string) map[string]any {
	return ruleProvider("classical", "text", path)
}

// buildRules emits the `rules:` array. Order matters — first match wins.
//
// overseas mode (default):
//
//	IP-CIDR,LAN,DIRECT (no-resolve)
//	GEOIP/RULE-SET ip_is_private DIRECT
//	[route.ad_block] RULE-SET,{category-ads-all,anti-ad,cname-ads},REJECT
//	[route.adult_block] DOMAIN-SUFFIX,<allow>,{DIRECT|out}
//	[route.adult_block] RULE-SET,{category-porn,nsfw},REJECT
//	RULE-SET,geosite-cn,DIRECT
//	RULE-SET,geoip-cn,DIRECT,no-resolve
//	MATCH,out
//
// whitelist mode:
//
//	IP-CIDR,LAN,DIRECT (no-resolve)
//	[route.ad_block] RULE-SET,{category-ads-all,anti-ad,cname-ads},REJECT
//	[route.adult_block] DOMAIN-SUFFIX,<allow>,{DIRECT|out}
//	[route.adult_block] RULE-SET,{category-porn,nsfw},REJECT
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
// the default-pool members) + a MATCH,default-pool fallback — so one terminal's
// whitelisted traffic all exits one node. IP-based whitelist (geoip /
// ip_cidr, no-resolve) still goes to `out` (hardcoded-IP apps don't drift,
// and no-resolve doesn't translate into a SUB-RULE condition).
//
// Proxied QUIC (UDP 443) is rejected so clients fall back to TCP: every
// sub-rule starts with quicRejectRule, and every rule that targets a proxy
// group directly is preceded by its guarded copy (see guardQUIC). DIRECT
// traffic keeps QUIC.
//
// Returns (rules, subRules). subRules is empty unless per-terminal is on.
func (r *Renderer) buildRules(outbounds []subscribe.Outbound) ([]string, map[string]any) {
	var rules []string
	subRules := map[string]any{}

	// proxied appends cond → target for a proxy-group target, preceded by
	// its QUIC guard (see quicRejectRule).
	proxied := func(cond, target, opts string) {
		rules = append(rules, guardQUIC(cond, opts), cond+","+target+opts)
	}

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
	// instead of rejected. One line per AdRuleSets entry — they are independent
	// lists, not fallbacks, so a hit in any of them rejects.
	if r.cfg.Route.AdBlock {
		for _, rs := range AdRuleSets {
			rules = append(rules, "RULE-SET,"+rs.Tag+",REJECT")
		}
	}

	// Adult-content blocking. Exemption rules come first: they are the
	// false-positive escape hatch and must win over the REJECT lines below.
	// The target mirrors what would happen without the block — DIRECT in
	// whitelist mode (where MATCH is DIRECT), the normal overseas outbound
	// otherwise. Note this means an exempt domain that is ALSO on the
	// whitelist goes direct, not through the pool; the config docs say not
	// to do that.
	//
	// Entries are normalized here because gateway.yaml is hand-editable:
	// accept "example.com", "+.example.com" and "*.example.com" alike.
	if r.cfg.Route.AdultBlock {
		exemptTarget := outSelector
		if r.cfg.Route.Mode == "whitelist" {
			exemptTarget = "DIRECT"
		}
		for _, d := range r.cfg.Route.AdultBlockAllow {
			d = strings.ToLower(strings.TrimSpace(d))
			d = strings.TrimPrefix(d, "+.")
			d = strings.TrimPrefix(d, "*.")
			d = strings.TrimPrefix(d, ".")
			if d == "" || strings.ContainsAny(d, " \t/:") {
				continue
			}
			cond := "DOMAIN-SUFFIX," + d
			if exemptTarget == "DIRECT" {
				rules = append(rules, cond+",DIRECT")
			} else {
				proxied(cond, exemptTarget, "")
			}
		}
		for _, rs := range AdultRuleSets {
			rules = append(rules, "RULE-SET,"+rs.Tag+",REJECT")
		}
	}

	// CN direct — must come before whitelist hits so CN endpoints of
	// global services (e.g. apple.com.cn) don't get routed via airport.
	rules = append(rules,
		"RULE-SET,"+rsGeositeCN+",DIRECT",
		"RULE-SET,"+rsGeoipCN+",DIRECT,no-resolve",
	)

	// Per-terminal: build the perterm sub-rule once. domainTarget below
	// dispatches domain whitelist hits into it. Each rule routes the
	// terminal to the fallback group carrying its [primary, secondary] HRW
	// pair, which mihomo backs with those two nodes. One terminal → one
	// egress at any given time, with automatic primary → secondary failover
	// when the primary fails mihomo's url-test.
	perterm := r.perTerminal && r.node.ClientSubnet != ""
	if perterm {
		slices := r.perTerminalSlices(outbounds)
		if len(slices) == 0 {
			// No routing members — disable perterm this render rather
			// than emit a sub-rule that dead-ends.
			perterm = false
		} else {
			subRules["perterm"] = append([]string{quicRejectRule}, slices...)
		}
	}

	// addDomain routes a domain-matching condition to either the perterm
	// sub-rule (per-terminal) or the `out` selector (default).
	addDomain := func(cond string) {
		if perterm {
			rules = append(rules, "SUB-RULE,("+cond+"),perterm")
			return
		}
		proxied(cond, outSelector, "")
	}

	// addIP is addDomain for IP-keyed conditions. no-resolve must survive
	// inside the SUB-RULE condition — verified against mihomo v1.19.26 on the
	// node (`mihomo -t` accepts "SUB-RULE,(RULE-SET,geoip-x,no-resolve),perterm").
	//
	// These used to go straight to `out` even with per-terminal on. `out`
	// leads with default-pool, a consistent-hashing load-balancer keyed on the
	// DESTINATION, so one terminal's IP-matched flows (QUIC to Google IPs,
	// Telegram MTProto) were spread across every egress while its
	// domain-matched flows stayed pinned — exactly the multi-IP pattern
	// per-terminal exists to prevent.
	addIP := func(cond string) {
		if perterm {
			rules = append(rules, "SUB-RULE,("+cond+",no-resolve),perterm")
			return
		}
		proxied(cond, outSelector, ",no-resolve")
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
	// (e.g. Gemini inside geosite-google) ahead of a broader tag. A pool's
	// rule_lists (external classical lists) are dispatched exactly like its
	// domain rule_sets.
	poolRouted := map[string]bool{}
	var classTags, classDefaultPool []string
	classResolved := false
	resolveClassMembers := func() {
		if classResolved {
			return
		}
		classTags = nodeTags(outbounds)
		classDefaultPool = r.defaultPoolMembers(outbounds)
		classResolved = true
	}
	for _, p := range r.pools {
		if p.IsClassPool() {
			resolveClassMembers()
			members := r.poolDispatchMembers(p, classTags, classDefaultPool)
			classPerTerm := p.PerTerminalEnabled() &&
				r.node.ClientSubnet != "" &&
				len(members) >= perTerminalFallbackDepth
			subName := "perterm-" + p.Name
			if classPerTerm {
				if slices := r.perTerminalSlicesFor(members, r.presentBackups(p.Name, outbounds), poolGroupPrefix(p.Name), p.Name); len(slices) > 0 {
					subRules[subName] = append([]string{quicRejectRule}, slices...)
				} else {
					classPerTerm = false
				}
			}
			for _, d := range p.DomainSuffix {
				if classPerTerm {
					rules = append(rules, "SUB-RULE,(DOMAIN-SUFFIX,"+d+"),"+subName)
				} else {
					proxied("DOMAIN-SUFFIX,"+d, p.Name, "")
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
					proxied("RULE-SET,"+tag, p.Name, noResolve)
				}
				poolRouted[tag] = true
			}
			// External classical lists (e.g. the Gemini list) are domain
			// rules, so they follow the same perterm dispatch as domain
			// rule_sets — no no-resolve.
			for _, rl := range p.RuleLists {
				if poolRouted[rl.Tag] {
					continue
				}
				if classPerTerm {
					rules = append(rules, "SUB-RULE,(RULE-SET,"+rl.Tag+"),"+subName)
				} else {
					proxied("RULE-SET,"+rl.Tag, p.Name, "")
				}
				poolRouted[rl.Tag] = true
			}
			continue
		}
		// Legacy pool (probe-gated subset of default-pool).
		for _, tag := range p.RuleSets {
			if poolRouted[tag] {
				continue
			}
			if perterm {
				if strings.HasPrefix(tag, "geoip-") {
					addIP("RULE-SET," + tag)
				} else {
					addDomain("RULE-SET," + tag)
				}
			} else {
				noResolve := ""
				if strings.HasPrefix(tag, "geoip-") {
					noResolve = ",no-resolve"
				}
				proxied("RULE-SET,"+tag, p.Name, noResolve)
			}
			poolRouted[tag] = true
		}
		for _, rl := range p.RuleLists {
			if poolRouted[rl.Tag] {
				continue
			}
			if perterm {
				addDomain("RULE-SET," + rl.Tag)
			} else {
				proxied("RULE-SET,"+rl.Tag, p.Name, "")
			}
			poolRouted[rl.Tag] = true
		}
	}

	if r.cfg.Route.Mode == "whitelist" {
		for _, tag := range r.cfg.Route.Whitelist.Geosites {
			if poolRouted[tag] {
				continue
			}
			addDomain("RULE-SET," + tag)
		}
		for _, sx := range r.cfg.Route.Whitelist.DomainSuffix {
			addDomain("DOMAIN-SUFFIX," + sx)
		}
		// IP-based whitelist (no-resolve; hardcoded-IP apps like Telegram
		// MTProto). Pinned per terminal like everything else — see addIP.
		for _, tag := range r.cfg.Route.Whitelist.Geoips {
			if poolRouted[tag] {
				continue
			}
			addIP("RULE-SET," + tag)
		}
		for _, cidr := range r.cfg.Route.Whitelist.IPCIDR {
			addIP("IP-CIDR," + cidr)
		}
		rules = append(rules, "MATCH,DIRECT")
	} else {
		// overseas mode: everything non-CN goes overseas. Per-terminal
		// dispatches the catch-all through perterm (which carries the QUIC
		// guard); else straight to out, behind an unconditional guard —
		// everything reaching this line is proxied.
		if perterm {
			rules = append(rules, "SUB-RULE,(MATCH),perterm")
		} else {
			rules = append(rules, quicRejectRule, "MATCH,"+outSelector)
		}
	}

	return rules, subRules
}
