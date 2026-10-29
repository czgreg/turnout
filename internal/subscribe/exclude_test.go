package subscribe

import (
	"slices"
	"testing"
)

// highMultiplier is the pattern configs/gateway.example.yaml recommends and
// 10.100.6.15 runs: 3x and above, matched on the multiplier, not the name.
const highMultiplier = `(^|[^0-9.]|[^0-9]\.)([3-9]|[1-9][0-9]+)(\.[0-9]+)?[xX×倍]`

func managerWith(t *testing.T, pattern string, tags ...string) *Manager {
	t.Helper()
	m := NewManagerWithFetch(nil, 0, "")
	if _, err := m.WithNodeExclude(pattern); err != nil {
		t.Fatalf("WithNodeExclude: %v", err)
	}
	obs := make([]Outbound, 0, len(tags))
	for _, tag := range tags {
		obs = append(obs, Outbound{"type": "trojan", "tag": tag})
	}
	m.lastResults = []SubscriptionResult{{Name: "test", Outbounds: obs}}
	return m
}

func tagsOf(obs []Outbound) []string {
	out := make([]string, 0, len(obs))
	for _, o := range obs {
		out = append(out, o.Tag())
	}
	return out
}

func TestNodeExclude_HighMultiplier(t *testing.T) {
	// Real tags from 10.100.6.15 (2026-10-29) plus edge cases.
	keep := []string{
		"wodi/日本TAT.2x",
		"wodi/香港家宽TBT.2x",
		"hutao/日本_BGP_A",
		"momo/🇭🇰香港06_WD",
		"x/香港 1.5x",
		"x/香港 2.5x",
		"x/香港 0.5x",
		"x/香港1x",
	}
	drop := []string{
		"wodi/台湾TC.6x | 专线",
		"wodi/香港家宽TC.6x | 专线",
		"wodi/印度HA.6x",
		"x/美国 3X",
		"x/日本 10x",
		"x/新加坡 3.5倍",
		"x/台湾 4×",
	}
	m := managerWith(t, highMultiplier, append(append([]string{}, keep...), drop...)...)

	if got := tagsOf(m.AllOutbounds()); !slices.Equal(got, keep) {
		t.Errorf("AllOutbounds = %v\nwant %v", got, keep)
	}
	if got := m.ExcludedTags(); !slices.Equal(got, drop) {
		t.Errorf("ExcludedTags = %v\nwant %v", got, drop)
	}
	// Snapshot keeps the full set so /api/nodes still shows what the
	// provider served.
	res, _ := m.Snapshot()
	if n := len(res[0].Outbounds); n != len(keep)+len(drop) {
		t.Errorf("Snapshot has %d outbounds, want %d", n, len(keep)+len(drop))
	}
}

func TestNodeExclude_EmptyKeepsAll(t *testing.T) {
	m := managerWith(t, "", "a/1", "b/6x")
	if n := len(m.AllOutbounds()); n != 2 {
		t.Errorf("AllOutbounds len = %d, want 2", n)
	}
	if ex := m.ExcludedTags(); ex != nil {
		t.Errorf("ExcludedTags = %v, want nil", ex)
	}
}

func TestNodeExclude_InvalidPattern(t *testing.T) {
	m := NewManagerWithFetch(nil, 0, "")
	if _, err := m.WithNodeExclude("(?!x)"); err == nil {
		t.Fatal("invalid pattern accepted")
	}
}
