package config

import (
	"strings"
	"testing"
)

func TestNodeExcludePatternValidation(t *testing.T) {
	c, err := loadPoolYAML(t, `
data_plane:
  url_test:
    node_exclude_pattern: "[0-9]x"
`)
	if err != nil {
		t.Fatalf("valid pattern rejected: %v", err)
	}
	if got := c.DataPlane.URLTest.NodeExcludePattern; got != "[0-9]x" {
		t.Errorf("NodeExcludePattern = %q", got)
	}

	// Fail closed: an ignored pattern would put excluded nodes back in routing.
	_, err = loadPoolYAML(t, `
data_plane:
  url_test:
    node_exclude_pattern: "(?!6x)"
`)
	if err == nil || !strings.Contains(err.Error(), "node_exclude_pattern") {
		t.Fatalf("invalid pattern: err = %v, want node_exclude_pattern error", err)
	}
}
