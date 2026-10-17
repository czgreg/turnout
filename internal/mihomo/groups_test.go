package mihomo

// Tests for the egress-interface binding in buildProxies.
//
// This is the P2 return-path guarantee: the host's default route points at
// the FIREWALL, so a proxy dial that followed it would leave for the
// firewall, be sent back, and defeat the tunnel. Pinning each proxy to the
// egress NIC is what prevents that — and the failure is invisible in tests
// that only compare protocol fields, which is why this file exists.

import (
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

func nodeOutbound(tag string) subscribe.Outbound {
	return subscribe.Outbound{
		"type": "trojan", "tag": tag,
		"server": "example.com", "server_port": 443,
		"password": "x", "tls": map[string]any{"enabled": true},
	}
}

func TestBuildProxies_BindsEgressIface(t *testing.T) {
	r := newTestRenderer(t)
	r.node.EgressIface = "ens18"

	proxies := r.buildProxies([]subscribe.Outbound{nodeOutbound("a/US-01"), nodeOutbound("b/US-02")})
	if len(proxies) != 2 {
		t.Fatalf("got %d proxies, want 2", len(proxies))
	}
	for i, p := range proxies {
		got, ok := p["interface-name"]
		if !ok {
			t.Errorf("proxy[%d] (%v) has no interface-name — dials would follow the default route into the firewall",
				i, p["name"])
			continue
		}
		if got != "ens18" {
			t.Errorf("proxy[%d] interface-name = %v, want ens18", i, got)
		}
	}
}

// An empty egress_iface must omit the key entirely rather than emit an empty
// string: mihomo would treat "" as a device name and fail to dial.
func TestBuildProxies_OmitsWhenEgressUnset(t *testing.T) {
	r := newTestRenderer(t)
	r.node.EgressIface = ""

	proxies := r.buildProxies([]subscribe.Outbound{nodeOutbound("a/US-01")})
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies, want 1", len(proxies))
	}
	if _, ok := proxies[0]["interface-name"]; ok {
		t.Error("interface-name must be absent when node.egress_iface is empty")
	}
}

// Internal outbound types (selector, direct, ...) are dropped, and dropping
// them must not disturb the binding applied to the node-bearing ones.
func TestBuildProxies_SkipsInternalTypes(t *testing.T) {
	r := newTestRenderer(t)
	r.node.EgressIface = "ens18"

	proxies := r.buildProxies([]subscribe.Outbound{
		{"type": "selector", "tag": "out"},
		nodeOutbound("a/US-01"),
		{"type": "direct", "tag": "direct"},
	})
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies, want 1 (internal types dropped)", len(proxies))
	}
	if proxies[0]["interface-name"] != "ens18" {
		t.Errorf("interface-name = %v, want ens18", proxies[0]["interface-name"])
	}
}

// Ingress must never be used as the dial interface: that NIC faces the
// firewall, so pinning it would send tunnel dials back into the firewall.
func TestBuildProxies_UsesEgressNotIngress(t *testing.T) {
	r := newTestRenderer(t)
	r.node = config.NodeConfig{
		ClientSubnet: "10.1.0.0/16",
		IngressIP:    "10.255.255.2",
		IngressIface: "ens19",
		EgressIface:  "ens18",
	}

	proxies := r.buildProxies([]subscribe.Outbound{nodeOutbound("a/US-01")})
	if len(proxies) != 1 {
		t.Fatalf("got %d proxies, want 1", len(proxies))
	}
	if got := proxies[0]["interface-name"]; got != "ens18" {
		t.Errorf("interface-name = %v, want ens18 (the egress NIC, never the ingress)", got)
	}
}
