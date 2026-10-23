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
pools:
  - name: ai-pool
    node_pattern: "美国|\\bUS"
    size: 4
    per_terminal: true
    rule_sets: [geosite-openai]
    domain_suffix: [gemini.google.com]
`)
	if err != nil {
		t.Fatalf("valid pools config rejected: %v", err)
	}
}
