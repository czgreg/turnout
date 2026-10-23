package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadPoolYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

// TestPoolsValidation pins the fail-closed checks in validatePools. A bad
// pool must never reach a render or the live mihomo process.
func TestPoolsValidation(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"invalid regex", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    node_pattern: "(?=us)"
`, "invalid node_pattern"},
		{"duplicate name", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
  - name: ai-pool
`, "duplicate pool name"},
		{"per terminal without subnet", `
node: {}
pools:
  - name: ai-pool
    per_terminal: true
`, "per_terminal requires node.client_subnet"},
		{"negative size", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    size: -1
`, "size must be >= 0"},
		{"empty domain", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    domain_suffix: [""]
`, "empty domain_suffix"},
		{"rule list without tag", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    rule_lists:
      - url: "https://example.com/x.list"
`, "tag is required"},
		{"rule list tag escapes dir", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    rule_lists:
      - tag: "../gemini"
        url: "https://example.com/x.list"
`, "invalid tag"},
		{"rule list tag looks like geoip", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    rule_lists:
      - tag: geoip-gemini
        url: "https://example.com/x.list"
`, "must not use the geoip- prefix"},
		{"rule list bad url", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    rule_lists:
      - tag: gemini
        url: "yfamilys.com/rule/Gemini.list"
`, "absolute http(s) URL"},
		{"rule list collides with whitelist", `
node: {client_subnet: "10.1.2.0/24"}
data_plane:
  route:
    whitelist:
      geosites: [gemini]
pools:
  - name: ai-pool
    rule_lists:
      - tag: gemini
        url: "https://example.com/x.list"
`, "already claimed"},
		{"rule list collides with pool rule_sets", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    rule_sets: [gemini]
    rule_lists:
      - tag: gemini
        url: "https://example.com/x.list"
`, "already claimed"},
		{"duplicate rule list tags", `
node: {client_subnet: "10.1.2.0/24"}
pools:
  - name: ai-pool
    rule_lists:
      - tag: gemini
        url: "https://example.com/a.list"
  - name: other-pool
    rule_lists:
      - tag: gemini
        url: "https://example.com/b.list"
`, "already claimed"},
	}
	for _, tc := range cases {
		_, err := loadPoolYAML(t, tc.yaml)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want substring %q", tc.name, err, tc.want)
		}
	}
}

func TestPoolsValidation_OK(t *testing.T) {
	_, err := loadPoolYAML(t, `
node: {client_subnet: "10.1.2.0/24"}
data_plane:
  route:
    whitelist:
      geosites: [geosite-openai]
pools:
  - name: ai-pool
    node_pattern: "美国|\\bUS"
    size: 4
    per_terminal: true
    rule_sets: [geosite-openai]
    rule_lists:
      - tag: gemini
        url: "https://yfamilys.com/rule/Gemini.list"
    domain_suffix: [gemini.google.com]
`)
	if err != nil {
		t.Fatalf("valid pools config rejected: %v", err)
	}
}
