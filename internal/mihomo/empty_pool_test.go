package mihomo

import (
	"strings"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// A pool with requires_passing turns on the probe listener. When the pool is
// empty (bootstrap render, or every subscription failed) the listener's
// `proxy: probe-out` is still emitted, so the group must exist too — an
// unresolved reference is a config mihomo rejects, and it would take the data
// plane down exactly when the node is trying to come up.
func TestEmptyPoolEmitsProbeOutStub(t *testing.T) {
	dp := config.DataPlaneConfig{}
	dp.ApplyDefaults()
	dp.TProxyPort = 7893

	r := NewRenderer(dp).
		WithNode(config.NodeConfig{ClientSubnet: "10.1.3.0/24", IngressIP: "10.1.3.15"}).
		WithPools([]config.PoolConfig{{Name: "ai-pool", RequiresPassing: []string{"openai"}}})

	out, err := r.RenderOnly(nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	s := string(out)

	if !strings.Contains(s, "proxy: probe-out") {
		t.Fatal("expected the probe listener to be emitted")
	}
	if !strings.Contains(s, "name: probe-out") {
		t.Fatal("listener references probe-out but no such proxy-group was rendered")
	}
}
