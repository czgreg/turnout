// Cross-subscription secondaries.
//
// The routing set was single-subscription 89% of the time on 10.100.6.15
// (2026-10-24..27) and 99.4% of terminal pairs shared one subscription, so a
// terminal's primary and secondary died together in each airport ingress
// incident. pairFor keeps the HRW primary and draws the secondary from another
// subscription's candidates.

package mihomo

import (
	"strings"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

var crossSubRouting = []string{
	"hutao/JP-A", "hutao/JP-B", "hutao/JP-C", "hutao/JP-D",
	"hutao/HK-A", "hutao/HK-B", "hutao/HK-C", "momo/HK-01",
}

var crossSubAlts = map[string][]string{
	"hutao": {"momo/HK-02", "momo/HK-03", "momo/SG-01"},
	"momo":  {"hutao/JP-E", "hutao/JP-F", "hutao/HK-D"},
}

func TestPairFor_PrimaryUnchangedSecondaryCrossSub(t *testing.T) {
	for _, u := range perTerminalUnits("192.168.0.0/16") {
		legacy := hrwTopN(u.key, crossSubRouting, perTerminalFallbackDepth)
		pair := pairFor(u.key, crossSubRouting, crossSubAlts)
		if len(pair) != 2 {
			t.Fatalf("%s: pair = %v", u.key, pair)
		}
		if pair[0] != legacy[0] {
			t.Fatalf("%s: primary changed %s → %s; terminals must keep their egress", u.key, legacy[0], pair[0])
		}
		if SubscriptionOf(pair[0]) == SubscriptionOf(pair[1]) {
			t.Fatalf("%s: secondary %s shares subscription with primary %s", u.key, pair[1], pair[0])
		}
	}
}

func TestPairFor_FallsBackWithoutAlts(t *testing.T) {
	alts := map[string][]string{"momo": crossSubAlts["momo"]} // no hutao entry
	for _, u := range perTerminalUnits("10.1.2.0/24") {
		pair := pairFor(u.key, crossSubRouting, alts)
		legacy := hrwTopN(u.key, crossSubRouting, perTerminalFallbackDepth)
		if SubscriptionOf(pair[0]) == "hutao" && (pair[0] != legacy[0] || pair[1] != legacy[1]) {
			t.Fatalf("%s: hutao primary without alts must use legacy top-2 %v, got %v", u.key, legacy, pair)
		}
	}
}

func crossSubOutbounds() []subscribe.Outbound {
	seen := map[string]bool{}
	var out []subscribe.Outbound
	add := func(tag string) {
		if !seen[tag] {
			seen[tag] = true
			out = append(out, nodeOutbound(tag))
		}
	}
	for _, t := range crossSubRouting {
		add(t)
	}
	for _, alts := range crossSubAlts {
		for _, t := range alts {
			add(t)
		}
	}
	return out
}

func TestCrossSubGroups_ReferencedAndBounded(t *testing.T) {
	r := newTestRenderer(t)
	r.node.ClientSubnet = "192.168.0.0/16"
	r.backups = map[string]map[string][]string{BackupClassDefault: crossSubAlts}
	outbounds := crossSubOutbounds()
	alts := r.presentBackups(BackupClassDefault, outbounds)

	groups := r.perTerminalFallbackGroupsFor(crossSubRouting, alts, perTerminalGroupPrefix, "http://probe.test/204", 30)
	// Each routing member pairs with one of its subscription's 3 alts.
	if max := len(crossSubRouting) * 3; len(groups) > max {
		t.Errorf("emitted %d groups, want ≤ %d (K × backups)", len(groups), max)
	}
	emitted := map[string]bool{}
	for _, g := range groups {
		emitted[g["name"].(string)] = true
		p := g["proxies"].([]string)
		if SubscriptionOf(p[0]) == SubscriptionOf(p[1]) {
			t.Errorf("group %v pairs one subscription", p)
		}
	}
	rules := r.perTerminalSlicesFor(crossSubRouting, alts, perTerminalGroupPrefix, defaultPool)
	for _, rule := range rules[:len(rules)-1] {
		parts := strings.Split(rule, ",")
		if !emitted[parts[len(parts)-1]] {
			t.Fatalf("rule %q references an unrendered group", rule)
		}
	}
}

func TestPresentBackups_DropsAbsentAndSameSub(t *testing.T) {
	r := newTestRenderer(t)
	r.backups = map[string]map[string][]string{BackupClassDefault: {
		"hutao": {"momo/HK-02", "momo/GONE", "hutao/JP-E"},
	}}
	got := r.presentBackups(BackupClassDefault, crossSubOutbounds())
	if want := []string{"momo/HK-02"}; len(got["hutao"]) != 1 || got["hutao"][0] != want[0] {
		t.Errorf("presentBackups = %v, want hutao:%v (absent and same-sub entries dropped)", got, want)
	}
	if r.presentBackups(BackupClassDefault, nil) != nil {
		t.Error("empty outbounds must disable backups (validate/bootstrap path)")
	}
}

func TestDNSOutIncludesBackups(t *testing.T) {
	r := newTestRenderer(t)
	r.routingMembers = append([]string(nil), crossSubRouting...)
	r.perTerminal = true
	r.backups = map[string]map[string][]string{BackupClassDefault: crossSubAlts}

	var dns map[string]any
	for _, g := range r.buildProxyGroups(crossSubOutbounds()) {
		if g["name"] == dnsOutSelector {
			dns = g
		}
	}
	if dns == nil {
		t.Fatal("dns-out not rendered")
	}
	members := map[string]bool{}
	for _, m := range dns["proxies"].([]string) {
		members[m] = true
	}
	subs := map[string]bool{}
	for m := range members {
		subs[SubscriptionOf(m)] = true
	}
	if len(subs) < 2 {
		t.Errorf("dns-out spans subscriptions %v; want ≥2 so one ingress outage cannot take DNS down", subs)
	}
	for _, alts := range crossSubAlts {
		for _, a := range alts {
			if !members[a] {
				t.Errorf("dns-out missing backup %s", a)
			}
		}
	}
}

func TestAssignmentForIP_MatchesRenderedPair(t *testing.T) {
	r := newTestRenderer(t)
	r.node.ClientSubnet = "192.168.0.0/16"
	r.routingMembers = append([]string(nil), crossSubRouting...)
	r.backups = map[string]map[string][]string{BackupClassDefault: crossSubAlts}
	outbounds := crossSubOutbounds()

	ip := "192.168.13.2"
	got, ok := r.AssignmentForIP(ip, outbounds)
	if !ok || len(got) != 2 {
		t.Fatalf("assignment = %v ok=%v", got, ok)
	}
	want := pairFor(perTerminalKey(ip, r.node.ClientSubnet), crossSubRouting, r.presentBackups(BackupClassDefault, outbounds))
	if got[0] != want[0] || got[1] != want[1] {
		t.Errorf("API pair %v != rendered pair %v", got, want)
	}
	name := PerTerminalGroupName(ip, r.node.ClientSubnet, got)
	found := false
	for _, g := range r.perTerminalFallbackGroups(outbounds, "http://probe.test/204", 30) {
		if g["name"] == name {
			found = true
		}
	}
	if !found {
		t.Errorf("API group %q is not a rendered group", name)
	}
}
