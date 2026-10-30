package apitls

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestManager(t *testing.T, dir string, sans []string, now func() time.Time) *Manager {
	t.Helper()
	m, err := New(Options{
		CertFile:    filepath.Join(dir, "cert.pem"),
		KeyFile:     filepath.Join(dir, "key.pem"),
		AutoManaged: true,
		SANs:        func() []string { return sans },
		Now:         now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestGenerateWritesFilesWithModes(t *testing.T) {
	dir := t.TempDir()
	m := newTestManager(t, dir, []string{"127.0.0.1", "10.100.6.15", "node-a"}, nil)

	st, err := os.Stat(filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("key.pem mode = %o, want 600", st.Mode().Perm())
	}
	st, err = os.Stat(filepath.Join(dir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("cert.pem mode = %o, want 644", st.Mode().Perm())
	}

	leaf := m.Leaf()
	if leaf.IsCA || !leaf.BasicConstraintsValid {
		t.Error("leaf must be CA:false with basic constraints present")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("ExtKeyUsage = %v, want serverAuth only", leaf.ExtKeyUsage)
	}
	if got := len(leaf.IPAddresses); got != 2 {
		t.Errorf("IP SANs = %v, want 2", leaf.IPAddresses)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "node-a" {
		t.Errorf("DNS SANs = %v, want [node-a]", leaf.DNSNames)
	}
	validity := leaf.NotAfter.Sub(leaf.NotBefore)
	if validity > DefaultValidity+time.Hour {
		t.Errorf("validity %s exceeds %s", validity, DefaultValidity)
	}
	if m.SPKIPin() == "" || m.Fingerprint() == "" {
		t.Error("pin / fingerprint empty")
	}
}

func TestReloadKeepsKeyAndPin(t *testing.T) {
	dir := t.TempDir()
	sans := []string{"127.0.0.1"}
	first := newTestManager(t, dir, sans, nil)
	pin, fp := first.SPKIPin(), first.Fingerprint()

	second := newTestManager(t, dir, sans, nil)
	if second.SPKIPin() != pin {
		t.Errorf("pin changed across restart: %s → %s", pin, second.SPKIPin())
	}
	if second.Fingerprint() != fp {
		t.Errorf("certificate re-issued on restart without cause")
	}
}

func TestRenewalKeepsPinChangesFingerprint(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	clock := func() time.Time { return now }
	m := newTestManager(t, dir, []string{"127.0.0.1"}, clock)
	pin, fp := m.SPKIPin(), m.Fingerprint()

	var renewedFP string
	m.OnRenewed = func(f string, _ time.Time) { renewedFP = f }

	if renewed, err := m.Refresh(); err != nil || renewed {
		t.Fatalf("Refresh before due: renewed=%v err=%v", renewed, err)
	}

	// Jump to 10 days before expiry: inside RenewBefore.
	now = m.Leaf().NotAfter.Add(-10 * 24 * time.Hour)
	renewed, err := m.Refresh()
	if err != nil || !renewed {
		t.Fatalf("Refresh when due: renewed=%v err=%v", renewed, err)
	}
	if m.SPKIPin() != pin {
		t.Error("renewal must keep the private key (pin changed)")
	}
	if m.Fingerprint() == fp {
		t.Error("renewal must issue a new certificate (fingerprint unchanged)")
	}
	if renewedFP != m.Fingerprint() {
		t.Errorf("OnRenewed got %s, want %s", renewedFP, m.Fingerprint())
	}
	if m.Leaf().NotAfter.Before(now.Add(300 * 24 * time.Hour)) {
		t.Errorf("renewed NotAfter %s too soon", m.Leaf().NotAfter)
	}
	// The renewed certificate is what a fresh load sees.
	again := newTestManager(t, dir, []string{"127.0.0.1"}, clock)
	if again.Fingerprint() != m.Fingerprint() {
		t.Error("renewed certificate not persisted")
	}
}

func TestSANChangeTriggersReissue(t *testing.T) {
	dir := t.TempDir()
	sans := []string{"127.0.0.1"}
	m, err := New(Options{
		CertFile:    filepath.Join(dir, "cert.pem"),
		KeyFile:     filepath.Join(dir, "key.pem"),
		AutoManaged: true,
		SANs:        func() []string { return sans },
	})
	if err != nil {
		t.Fatal(err)
	}
	fp := m.Fingerprint()
	sans = []string{"127.0.0.1", "192.168.1.9"}
	renewed, err := m.Refresh()
	if err != nil || !renewed {
		t.Fatalf("Refresh after SAN change: renewed=%v err=%v", renewed, err)
	}
	if m.Fingerprint() == fp {
		t.Error("certificate not re-issued for new SAN")
	}
	if len(m.Leaf().IPAddresses) != 2 {
		t.Errorf("IP SANs = %v", m.Leaf().IPAddresses)
	}
	// Same set in a different order is not a change.
	sans = []string{"192.168.1.9", "127.0.0.1"}
	if renewed, _ := m.Refresh(); renewed {
		t.Error("reordered SANs must not re-issue")
	}
}

func TestOperatorProvidedNeverRenews(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	clock := func() time.Time { return now }
	auto := newTestManager(t, dir, []string{"127.0.0.1"}, clock)
	fp := auto.Fingerprint()

	own, err := New(Options{
		CertFile:    filepath.Join(dir, "cert.pem"),
		KeyFile:     filepath.Join(dir, "key.pem"),
		AutoManaged: false,
		SANs:        func() []string { return []string{"something-else"} },
		Now:         clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	var expiring bool
	own.OnExpiring = func(time.Time) { expiring = true }
	now = own.Leaf().NotAfter.Add(-time.Hour)
	renewed, err := own.Refresh()
	if err != nil || renewed {
		t.Fatalf("operator-provided renewed=%v err=%v", renewed, err)
	}
	if own.Fingerprint() != fp {
		t.Error("operator-provided certificate must be left alone")
	}
	if !expiring {
		t.Error("OnExpiring not raised")
	}
}

func TestMissingPairIsAnErrorWhenNotAutoManaged(t *testing.T) {
	dir := t.TempDir()
	_, err := New(Options{
		CertFile: filepath.Join(dir, "cert.pem"),
		KeyFile:  filepath.Join(dir, "key.pem"),
	})
	if err == nil {
		t.Fatal("expected load error for missing operator-provided pair")
	}
}

func TestPinFromCertFileAndVerifyPin(t *testing.T) {
	dir := t.TempDir()
	m := newTestManager(t, dir, []string{"127.0.0.1"}, nil)

	pin, err := PinFromCertFile(filepath.Join(dir, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if pin != m.SPKIPin() {
		t.Errorf("PinFromCertFile = %s, want %s", pin, m.SPKIPin())
	}

	// Not httptest.StartTLS: it installs its own certificate and tls.Config
	// prefers Certificates over GetCertificate when there is no SNI.
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	url := "https://" + ln.Addr().String()

	client := func(pin string) *http.Client {
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			InsecureSkipVerify:    true,
			VerifyPeerCertificate: VerifyPin(pin),
		}}}
	}
	if resp, err := client(pin).Get(url); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("matching pin: resp=%v err=%v", resp, err)
	}
	if _, err := client("AAAA" + pin[4:]).Get(url); err == nil {
		t.Fatal("mismatching pin must fail the handshake")
	}
}

func TestNodeSANs(t *testing.T) {
	sans := NodeSANs("10.100.6.15", []string{" gw.example.internal ", "10.100.6.15", ""})
	want := map[string]bool{"127.0.0.1": false, "::1": false, "localhost": false, "10.100.6.15": false, "gw.example.internal": false}
	count := map[string]int{}
	for _, s := range sans {
		count[s]++
		if _, ok := want[s]; ok {
			want[s] = true
		}
	}
	for s, seen := range want {
		if !seen {
			t.Errorf("missing SAN %q in %v", s, sans)
		}
	}
	for s, n := range count {
		if n > 1 {
			t.Errorf("SAN %q listed %d times", s, n)
		}
	}
	for _, s := range sans {
		if ip := net.ParseIP(s); ip != nil && ip.To4() == nil && s != "::1" {
			t.Errorf("unexpected IPv6 SAN %q", s)
		}
	}
}
