package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestXBorderLogDefaultsOnlyWhenEnabled(t *testing.T) {
	var off XBorderLogConfig
	off.applyDefaults()
	if off != (XBorderLogConfig{}) {
		t.Errorf("disabled block must stay zero so yaml round-trip adds nothing: %+v", off)
	}
	on := XBorderLogConfig{Enabled: true, Address: "192.0.2.50:514"}
	on.applyDefaults()
	want := XBorderLogConfig{Enabled: true, Address: "192.0.2.50:514", Framing: "lf",
		Facility: "local5", AppName: "turnout-xborder", PollInterval: time.Second, QueueSize: 10000}
	if on != want {
		t.Errorf("defaults = %+v, want %+v", on, want)
	}
}

func TestXBorderLogDisabledOmittedFromYAML(t *testing.T) {
	b, err := yaml.Marshal(&Config{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "xborder_log") {
		t.Errorf("a node that never enabled xborder_log must not grow the block on write-back:\n%s", b)
	}
}

func TestValidateXBorderLog(t *testing.T) {
	base := func() *Config {
		c := &Config{XBorderLog: XBorderLogConfig{Enabled: true, Address: "192.0.2.50:514"}}
		c.DataPlane.LogLevel = "info"
		c.DataPlane.ClashAPI.ExternalController = "127.0.0.1:9090"
		c.XBorderLog.applyDefaults()
		return c
	}
	if err := base().validateXBorderLog(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*Config){
		"missing address":  func(c *Config) { c.XBorderLog.Address = "" },
		"address no port":  func(c *Config) { c.XBorderLog.Address = "192.0.2.50" },
		"bad framing":      func(c *Config) { c.XBorderLog.Framing = "nul" },
		"bad facility":     func(c *Config) { c.XBorderLog.Facility = "user" },
		"app name space":   func(c *Config) { c.XBorderLog.AppName = "a b" },
		"poll too fast":    func(c *Config) { c.XBorderLog.PollInterval = 10 * time.Millisecond },
		"queue too small":  func(c *Config) { c.XBorderLog.QueueSize = 5 },
		"log level warn":   func(c *Config) { c.DataPlane.LogLevel = "warning" },
		"no clash api":     func(c *Config) { c.DataPlane.ClashAPI.ExternalController = "" },
	}
	for name, mut := range cases {
		c := base()
		mut(c)
		if err := c.validateXBorderLog(); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	off := &Config{}
	if err := off.validateXBorderLog(); err != nil {
		t.Errorf("disabled must not validate: %v", err)
	}
}

// Load must refuse an enabled block with no address rather than start a
// node that ships nothing.
func TestLoadRejectsEnabledXBorderWithoutAddress(t *testing.T) {
	src, err := os.ReadFile("../../configs/gateway.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(src), "xborder_log:\n  enabled: false", "xborder_log:\n  enabled: true", 1)
	if s == string(src) {
		t.Fatal("example must contain an `xborder_log:\\n  enabled: false` block")
	}
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "xborder_log.address") {
		t.Errorf("Load = %v, want xborder_log.address error", err)
	}
}
