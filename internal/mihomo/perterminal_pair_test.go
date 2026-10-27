// Pair-keyed per-terminal groups.
//
// Regression guard for the 2026-10-23 fix: per-terminal fallback groups used
// to be emitted once per terminal unit (1024 buckets for a /16, ×2 class
// pools). mihomo runs a health check for every group the moment a config is
// applied, so each hot reload fired ~4k dials at 8 nodes and took 6-7s on
// 10.100.6.15. Groups are now keyed by the HRW pair, which is semantically
// identical (alive state lives on the shared proxy object) and bounded by
// C(K,2).

package mihomo

import (
	"strings"
	"testing"
)

func TestPairGroupSuffix_OrderMattersAndDepth(t *testing.T) {
	a := pairGroupSuffix([]string{"n1", "n2"})
	b := pairGroupSuffix([]string{"n2", "n1"})
	if a == "" || b == "" {
		t.Fatal("two members must produce a suffix")
	}
	if a == b {
		t.Errorf("fallback order is semantic; [n1,n2] and [n2,n1] must differ (both %q)", a)
	}
	if got := pairGroupSuffix([]string{"n1"}); got != "" {
		t.Errorf("one member must produce no suffix, got %q", got)
	}
	if !strings.HasPrefix(a, pairGroupInfix) {
		t.Errorf("suffix %q lacks pair infix %q", a, pairGroupInfix)
	}
	// Stable across calls — the API derives the same name independently.
	if again := pairGroupSuffix([]string{"n1", "n2"}); again != a {
		t.Errorf("suffix not deterministic: %q vs %q", a, again)
	}
}

// A /16 has 1024 terminal units but only K(K-1)=56 ordered-pair groups,
// and every SRC-IP rule must reference a group that was actually emitted.
func TestPerTerminalPairGroups_DeduplicatedAndReferenced(t *testing.T) {
	r := newTestRenderer(t)
	r.node.ClientSubnet = "192.168.0.0/16"
	members := liveRoutingPool // 8 members (hrwdist_test.go)

	groups := r.perTerminalFallbackGroupsFor(members, nil, perTerminalGroupPrefix, "http://probe.test/204", 30)
	maxPairs := len(members) * (len(members) - 1) // ordered: [A,B] != [B,A]
	if len(groups) != maxPairs {
		t.Errorf("emitted %d groups for a %d-member pool; want %d ordered pairs", len(groups), len(members), maxPairs)
	}

	emitted := make(map[string]bool, len(groups))
	for _, g := range groups {
		name, _ := g["name"].(string)
		if emitted[name] {
			t.Errorf("duplicate group %q", name)
		}
		emitted[name] = true
		proxies, _ := g["proxies"].([]string)
		if len(proxies) != perTerminalFallbackDepth {
			t.Errorf("group %q has %d members, want %d", name, len(proxies), perTerminalFallbackDepth)
		}
		if g["type"] != "fallback" {
			t.Errorf("group %q type = %v", name, g["type"])
		}
	}

	rules := r.perTerminalSlicesFor(members, nil, perTerminalGroupPrefix, defaultPool)
	units := perTerminalUnits(r.node.ClientSubnet)
	if len(rules) != len(units)+1 {
		t.Fatalf("rules = %d, want %d units + MATCH", len(rules), len(units))
	}
	for _, rule := range rules[:len(rules)-1] {
		parts := strings.Split(rule, ",")
		target := parts[len(parts)-1]
		if !emitted[target] {
			t.Fatalf("rule %q references unrendered group %q", rule, target)
		}
	}
	if want := "MATCH," + defaultPool; rules[len(rules)-1] != want {
		t.Errorf("last rule = %q, want %q", rules[len(rules)-1], want)
	}

	// The API-facing name must be the one the renderer emitted.
	key := perTerminalKey("192.168.1.126", r.node.ClientSubnet)
	assigned := hrwTopN(key, members, perTerminalFallbackDepth)
	if name := PerTerminalGroupName("192.168.1.126", r.node.ClientSubnet, assigned); !emitted[name] {
		t.Errorf("API group name %q was not emitted by the renderer", name)
	}
}

// Host mode (/24) keeps one rule per host but still shares groups by pair.
func TestPerTerminalPairGroups_HostMode(t *testing.T) {
	r := newTestRenderer(t) // ClientSubnet 10.1.2.0/24
	members := []string{"n1", "n2", "n3"}
	groups := r.perTerminalFallbackGroupsFor(members, nil, perTerminalGroupPrefix, "http://probe.test/204", 30)
	if len(groups) != 6 {
		t.Errorf("emitted %d groups, want K(K-1)=6 ordered pairs", len(groups))
	}
	if got := len(r.perTerminalSlicesFor(members, nil, perTerminalGroupPrefix, defaultPool)); got != 255 {
		t.Errorf("rules = %d, want 254 hosts + MATCH", got)
	}
}
