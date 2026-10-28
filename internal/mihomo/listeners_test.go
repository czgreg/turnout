package mihomo

import (
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/dataplane"
	"gopkg.in/yaml.v3"
)

// listenerByName returns the rendered listener with the given name, or nil.
func listenerByName(doc map[string]any, name string) map[string]any {
	listeners, _ := doc["listeners"].([]any)
	for _, l := range listeners {
		m, _ := l.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	return nil
}

func renderDocForTest(t *testing.T, r *Renderer, withOutbounds bool) map[string]any {
	t.Helper()
	var obs = sampleOutbounds()
	if !withOutbounds {
		obs = nil
	}
	body, err := r.Write(obs)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, body)
	}
	return doc
}

// The egress listener is pinned to `out` so the API's egress probe skips the
// rule table. Through mixed-port, whitelist mode sent the non-whitelisted
// echo host (ipinfo.io) to MATCH,DIRECT, and /api/proxies/active reported
// the office's direct exit (AWS Oregon) as default-pool's while traffic
// really left through a Japan node (2026-10-28).
func TestRenderer_EgressListenerPinnedToOut(t *testing.T) {
	r := newTestRenderer(t)
	r.cfg.Route.Mode = "whitelist"
	r.cfg.Route.Whitelist = config.WhitelistConfig{
		Geosites: config.StringList{"geosite-google"},
	}
	doc := renderDocForTest(t, r, true)

	l := listenerByName(doc, "turnout-egress")
	if l == nil {
		t.Fatal("turnout-egress listener missing")
	}
	if l["proxy"] != outSelector {
		t.Errorf("turnout-egress proxy = %v, want %q", l["proxy"], outSelector)
	}
	if l["listen"] != "127.0.0.1" {
		t.Errorf("turnout-egress listen = %v, want loopback only", l["listen"])
	}
	if l["port"] != TurnoutEgressProbePort {
		t.Errorf("turnout-egress port = %v, want %d", l["port"], TurnoutEgressProbePort)
	}
	// No probe-gated pool → no site-probe listener.
	if listenerByName(doc, "turnout-probe") != nil {
		t.Error("turnout-probe listener rendered without a probe-gated pool")
	}
}

// Bootstrap (no outbounds) still renders `out` as a DIRECT stub, so the
// egress listener's hard reference must resolve there too.
func TestRenderer_EgressListenerBootstrap(t *testing.T) {
	r := newTestRenderer(t)
	doc := renderDocForTest(t, r, false)

	l := listenerByName(doc, "turnout-egress")
	if l == nil {
		t.Fatal("turnout-egress listener missing in bootstrap render")
	}
	groups, _ := doc["proxy-groups"].([]any)
	found := false
	for _, g := range groups {
		m, _ := g.(map[string]any)
		if m["name"] == l["proxy"] {
			found = true
		}
	}
	if !found {
		t.Errorf("turnout-egress points at %v, which is not a rendered group", l["proxy"])
	}
}

// The renderer and the API agree on the port only by convention; pin it.
func TestEgressProbePortMatchesDataplane(t *testing.T) {
	if TurnoutEgressProbePort != dataplane.TurnoutEgressProbePort {
		t.Errorf("mihomo.TurnoutEgressProbePort = %d, dataplane.TurnoutEgressProbePort = %d",
			TurnoutEgressProbePort, dataplane.TurnoutEgressProbePort)
	}
	if want := "http://127.0.0.1:11082"; dataplane.TurnoutEgressProbeURL != want {
		t.Errorf("dataplane.TurnoutEgressProbeURL = %q, want %q", dataplane.TurnoutEgressProbeURL, want)
	}
	if TurnoutEgressProbePort == TurnoutInternalProxyPort || TurnoutEgressProbePort == probePort {
		t.Errorf("egress probe port %d collides with another loopback listener", TurnoutEgressProbePort)
	}
}
