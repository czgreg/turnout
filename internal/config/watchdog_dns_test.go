package config

import (
	"testing"
	"time"
)

func TestWatchdogDNSProbeDefaults(t *testing.T) {
	var w WatchdogConfig
	w.applyDefaults()
	if !w.Checks.CheckDNSProbe() {
		t.Error("dns_probe must default ON (nil pointer)")
	}
	if w.Checks.DNSProbeDomain != "www.youtube.com" {
		t.Errorf("dns_probe_domain = %q, want www.youtube.com", w.Checks.DNSProbeDomain)
	}
	if w.Checks.DNSProbeTimeout != 3*time.Second {
		t.Errorf("dns_probe_timeout = %s, want 3s", w.Checks.DNSProbeTimeout)
	}

	off := false
	w.Checks.DNSProbe = &off
	if w.Checks.CheckDNSProbe() {
		t.Error("explicit dns_probe: false must disable the check")
	}
}

func TestWatchdogDNSProbeOverridesPreserved(t *testing.T) {
	var w WatchdogConfig
	w.Checks.DNSProbeDomain = "claude.ai"
	w.Checks.DNSProbeTimeout = 5 * time.Second
	w.applyDefaults()
	if w.Checks.DNSProbeDomain != "claude.ai" {
		t.Errorf("explicit domain overwritten: %q", w.Checks.DNSProbeDomain)
	}
	if w.Checks.DNSProbeTimeout != 5*time.Second {
		t.Errorf("explicit timeout overwritten: %s", w.Checks.DNSProbeTimeout)
	}
}
