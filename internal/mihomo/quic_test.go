package mihomo

import (
	"strings"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

func rulesOf(t *testing.T, doc map[string]any) []string {
	t.Helper()
	raw, _ := doc["rules"].([]any)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		s, _ := r.(string)
		out = append(out, s)
	}
	return out
}

func subRulesOf(doc map[string]any) map[string][]string {
	raw, _ := doc["sub-rules"].(map[string]any)
	out := map[string][]string{}
	for name, v := range raw {
		list, _ := v.([]any)
		for _, r := range list {
			s, _ := r.(string)
			out[name] = append(out[name], s)
		}
	}
	return out
}

// assertProxiedRulesGuarded checks that every top-level rule targeting a proxy
// group directly is immediately preceded by its QUIC guard, and returns how
// many such rules it saw. SUB-RULE lines are covered by the guard heading
// each sub-rule; DIRECT/REJECT targets keep QUIC.
func assertProxiedRulesGuarded(t *testing.T, rules []string) int {
	t.Helper()
	n := 0
	for i, rule := range rules {
		if strings.HasPrefix(rule, "AND,") || strings.HasPrefix(rule, "SUB-RULE,") {
			continue
		}
		fields := strings.Split(rule, ",")
		opts := ""
		if fields[len(fields)-1] == "no-resolve" {
			opts = ",no-resolve"
			fields = fields[:len(fields)-1]
		}
		target := fields[len(fields)-1]
		if target == "DIRECT" || target == "REJECT" {
			continue
		}
		n++
		want := quicRejectRule
		if fields[0] != "MATCH" {
			want = guardQUIC(strings.Join(fields[:len(fields)-1], ","), opts)
		}
		if i == 0 || rules[i-1] != want {
			prev := ""
			if i > 0 {
				prev = rules[i-1]
			}
			t.Errorf("proxied rule %q not guarded: previous rule %q, want %q", rule, prev, want)
		}
	}
	return n
}

// Per-terminal whitelist (the production shape on 10.100.6.15): every proxied
// flow goes through a sub-rule, so each sub-rule must open with the guard —
// and nothing at top level may reject QUIC, or MATCH,DIRECT traffic loses it.
func TestBuildRules_QUICGuardPerTerminal(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.URLTest.NodePattern = `日本|JP|SG`
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-openai", "geosite-google"},
		Geoips:   config.StringList{"geoip-telegram"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:         "ai-pool",
		NodePattern:  `美国|🇺🇸|\bUS`,
		Size:         2,
		PerTerminal:  poolBool(true),
		RuleSets:     []string{"geosite-openai"},
		DomainSuffix: []string{"gemini.google.com"},
	}}).WithLoadBalance(true)
	r.node.ClientSubnet = "10.1.2.0/29"
	doc := renderDocForTest(t, r, true)

	subs := subRulesOf(doc)
	for _, name := range []string{"perterm", "perterm-ai-pool"} {
		sr := subs[name]
		if len(sr) == 0 {
			t.Fatalf("sub-rule %q missing", name)
		}
		if sr[0] != quicRejectRule {
			t.Errorf("sub-rule %q starts with %q, want %q", name, sr[0], quicRejectRule)
		}
	}

	rules := rulesOf(t, doc)
	for _, rule := range rules {
		if rule == quicRejectRule {
			t.Errorf("unconditional QUIC reject at top level in whitelist mode — DIRECT traffic would lose QUIC")
		}
	}
	if last := rules[len(rules)-1]; last != "MATCH,DIRECT" {
		t.Errorf("last rule = %q, want MATCH,DIRECT", last)
	}
	assertProxiedRulesGuarded(t, rules)
}

// Without per-terminal, whitelist and shared-pool rules target `out` / the
// pool directly, so each needs its own guard — including no-resolve IP rules.
func TestBuildRules_QUICGuardDirectTargets(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites:     config.StringList{"geosite-google", "geosite-openai"},
		DomainSuffix: config.StringList{"claude.ai"},
		Geoips:       config.StringList{"geoip-telegram"},
		IPCIDR:       config.StringList{"91.108.4.0/22"},
	}
	r = r.WithPools([]config.PoolConfig{{
		Name:         "ai-pool",
		NodePattern:  `美国|🇺🇸|\bUS`,
		PerTerminal:  poolBool(false),
		RuleSets:     []string{"geosite-openai"},
		DomainSuffix: []string{"gemini.google.com"},
	}})
	doc := renderDocForTest(t, r, true)
	rules := rulesOf(t, doc)

	if n := assertProxiedRulesGuarded(t, rules); n < 6 {
		t.Errorf("saw %d proxied rules, want at least 6 (pool domain + rule-set, 2 whitelist kinds × domain/IP)", n)
	}
	for _, want := range []string{
		guardQUIC("RULE-SET,geoip-telegram", ",no-resolve"),
		guardQUIC("IP-CIDR,91.108.4.0/22", ",no-resolve"),
		guardQUIC("DOMAIN-SUFFIX,gemini.google.com", ""),
	} {
		found := false
		for _, rule := range rules {
			if rule == want {
				found = true
			}
		}
		if !found {
			t.Errorf("missing guard %q", want)
		}
	}
	if last := rules[len(rules)-1]; last != "MATCH,DIRECT" {
		t.Errorf("last rule = %q, want MATCH,DIRECT", last)
	}
}

// Overseas mode without per-terminal: everything past CN-direct is proxied,
// so the catch-all gets the unconditional guard right before MATCH,out.
func TestBuildRules_QUICGuardOverseasCatchAll(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.Route.Mode = "overseas"
	doc := renderDocForTest(t, r, true)
	rules := rulesOf(t, doc)

	n := len(rules)
	if n < 2 || rules[n-1] != "MATCH,"+outSelector || rules[n-2] != quicRejectRule {
		t.Errorf("tail = %v, want [%q, MATCH,%s]", rules[max(0, n-2):], quicRejectRule, outSelector)
	}
	assertProxiedRulesGuarded(t, rules)
}
