package config

import (
	"strings"
	"testing"
)

func TestAPITLSDefaultsOn(t *testing.T) {
	c, err := loadPoolYAML(t, `
api:
  listen: "0.0.0.0:18080"
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !c.API.TLS.IsEnabled() {
		t.Error("api.tls must default to enabled")
	}
	if !c.API.TLS.AutoManaged() {
		t.Error("api.tls must default to auto-managed")
	}
	cert, key := c.API.TLS.Paths()
	if cert != DefaultAPITLSDir+"/cert.pem" || key != DefaultAPITLSDir+"/key.pem" {
		t.Errorf("Paths() = %s, %s", cert, key)
	}
}

func TestAPITLSDisabledNeedsLoopback(t *testing.T) {
	_, err := loadPoolYAML(t, `
api:
  listen: "0.0.0.0:18080"
  tls:
    enabled: false
`)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("tls off on 0.0.0.0: err = %v, want loopback error", err)
	}
	for _, listen := range []string{"127.0.0.1:18080", "[::1]:18080", "localhost:18080"} {
		if _, err := loadPoolYAML(t, "api:\n  listen: \""+listen+"\"\n  tls:\n    enabled: false\n"); err != nil {
			t.Errorf("tls off on %s rejected: %v", listen, err)
		}
	}
}

func TestAPITLSOperatorPairMustBeComplete(t *testing.T) {
	_, err := loadPoolYAML(t, `
api:
  tls:
    cert_file: /etc/turnout/api.crt
`)
	if err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("cert without key: err = %v", err)
	}
	c, err := loadPoolYAML(t, `
api:
  tls:
    cert_file: /etc/turnout/api.crt
    key_file: /etc/turnout/api.key
    extra_sans: ["gw.corp.internal", "203.0.113.5"]
`)
	if err != nil {
		t.Fatalf("complete pair rejected: %v", err)
	}
	if c.API.TLS.AutoManaged() {
		t.Error("operator-provided pair reported as auto-managed")
	}
	if len(c.API.TLS.ExtraSANs) != 2 {
		t.Errorf("ExtraSANs = %v", c.API.TLS.ExtraSANs)
	}
}
