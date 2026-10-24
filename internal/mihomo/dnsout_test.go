package mihomo

import "testing"

// Resolver traffic must transit the scorer's qualified routing set, not
// default-pool. On 2026-10-24 default-pool's consistent hash sent 1.1.1.1:443
// to an unqualified candidate that could not reach it; every whitelisted DNS
// lookup SERVFAILed while the routing pool was healthy.
func TestProxyGroups_DNSOutUsesRoutingMembers(t *testing.T) {
	r := newTestRenderer(t)
	r.routingMembers = []string{"ash/🇺🇸US-IEPL-01", "ctc-02/US-C30-01", "yuyun/SG-01"}
	r.perTerminal = true

	var dns map[string]any
	for _, g := range r.buildProxyGroups(sampleOutbounds()) {
		if g["name"] == dnsOutSelector {
			dns = g
			break
		}
	}
	if dns == nil {
		t.Fatalf("no %q group rendered", dnsOutSelector)
	}
	if dns["type"] != "load-balance" || dns["strategy"] != "consistent-hashing" {
		t.Errorf("dns-out = %v, want load-balance/consistent-hashing", dns["type"])
	}
	proxies, _ := dns["proxies"].([]string)
	if len(proxies) != len(r.routingMembers) {
		t.Fatalf("dns-out members = %v, want %v", proxies, r.routingMembers)
	}
	for i := range proxies {
		if proxies[i] != r.routingMembers[i] {
			t.Fatalf("dns-out members = %v, want %v", proxies, r.routingMembers)
		}
	}
	if dns["lazy"] != true {
		t.Errorf("dns-out lazy = %v, want true (cadence tied to DNS traffic)", dns["lazy"])
	}
}

func TestProxyGroups_DNSOutDirectStubWithoutNodes(t *testing.T) {
	r := newTestRenderer(t)
	var dns map[string]any
	for _, g := range r.buildProxyGroups(nil) {
		if g["name"] == dnsOutSelector {
			dns = g
			break
		}
	}
	if dns == nil {
		t.Fatalf("no %q stub rendered for the empty-pool case", dnsOutSelector)
	}
	proxies, _ := dns["proxies"].([]string)
	if len(proxies) != 1 || proxies[0] != "DIRECT" {
		t.Errorf("stub members = %v, want [DIRECT]", proxies)
	}
}
