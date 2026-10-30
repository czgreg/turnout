// Package apitls owns the certificate the control-plane API presents.
//
// Why self-signed, per node: the API is reachable from the whole office LAN
// (nft accepts 18080 from every source since 2026-10-22) and carries a
// bearer token on every request. Plain HTTP puts that token in front of
// anyone on the same segment. There is no internal CA to enrol with and
// the nodes are reached by IP, so each node mints its own key + leaf
// certificate and callers pin the public key (SPKI SHA-256) or trust the
// certificate file out of band.
//
// Lifecycle (auto-managed mode, the default):
//   - first start: generate an ECDSA P-256 key and a 397-day certificate
//     under /var/lib/turnout/api-tls/. 397 days keeps the certificate
//     importable into macOS's trust store (825-day cap) and under Chrome's
//     398-day limit.
//   - renewal: Refresh (run daily) re-signs with the SAME key when fewer
//     than RenewBefore remain or the SAN set changed. Callers that pin the
//     public key keep working; only browsers see a "new" certificate.
//   - key rotation is manual (delete the files, restart) because every
//     pinned caller must be updated afterwards.
//
// Operator-provided mode (cert_file + key_file set): the pair is loaded
// as-is; nothing is generated or renewed, and Refresh only reports
// impending expiry through OnExpiring.
package apitls

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultValidity is the lifetime of a freshly signed certificate.
	DefaultValidity = 397 * 24 * time.Hour
	// DefaultRenewBefore is how long before NotAfter Refresh re-signs.
	DefaultRenewBefore = 30 * 24 * time.Hour
)

// Options configures a Manager.
type Options struct {
	CertFile string
	KeyFile  string
	// AutoManaged: generate when missing, renew when due. false = load only.
	AutoManaged bool
	// SANs returns the names the auto-managed certificate must cover. It is
	// called on every Refresh so an address change is picked up without a
	// restart. Entries may be IPs or DNS names; see NodeSANs.
	SANs func() []string

	Validity    time.Duration
	RenewBefore time.Duration
	// Now is overridable for tests.
	Now func() time.Time
}

// Manager serves the current certificate to tls.Config and renews it.
type Manager struct {
	opts Options
	mu   sync.Mutex // serializes Refresh / file writes
	cur  atomic.Pointer[tls.Certificate]

	// OnRenewed fires after a successful re-sign with the new certificate's
	// fingerprint. Operators need it: browsers that trusted the old
	// certificate will prompt again.
	OnRenewed func(fingerprint string, notAfter time.Time)
	// OnExpiring fires from Refresh in operator-provided mode when fewer
	// than RenewBefore remain. Auto-managed mode renews instead.
	OnExpiring func(notAfter time.Time)
}

// New loads the certificate pair, generating it first in auto-managed mode
// when the key file is absent.
func New(opts Options) (*Manager, error) {
	if opts.Validity == 0 {
		opts.Validity = DefaultValidity
	}
	if opts.RenewBefore == 0 {
		opts.RenewBefore = DefaultRenewBefore
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.SANs == nil {
		opts.SANs = func() []string { return nil }
	}
	m := &Manager{opts: opts}

	if opts.AutoManaged {
		if _, err := os.Stat(opts.KeyFile); errors.Is(err, os.ErrNotExist) {
			if err := m.generate(); err != nil {
				return nil, err
			}
			return m, nil
		}
		if _, err := os.Stat(opts.CertFile); errors.Is(err, os.ErrNotExist) {
			// Key survived but the certificate did not (interrupted write,
			// manual cleanup). Re-issue on the existing key so pins hold.
			key, err := loadKey(opts.KeyFile)
			if err != nil {
				return nil, err
			}
			if err := m.issue(key); err != nil {
				return nil, err
			}
			return m, nil
		}
	}
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("apitls: load %s / %s: %w", opts.CertFile, opts.KeyFile, err)
	}
	if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, fmt.Errorf("apitls: parse %s: %w", opts.CertFile, err)
	}
	m.cur.Store(&cert)
	// A certificate that is already due is renewed before the first
	// handshake; the daily loop would otherwise leave it stale for a day.
	if opts.AutoManaged {
		if _, err := m.Refresh(); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// GetCertificate is the tls.Config hook; it reads the current certificate
// atomically so a renewal takes effect on the next handshake.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return m.cur.Load(), nil
}

// TLSConfig returns a server config bound to this manager.
func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: m.GetCertificate,
	}
}

// Leaf returns the parsed current certificate.
func (m *Manager) Leaf() *x509.Certificate { return m.cur.Load().Leaf }

// Fingerprint is the SHA-256 of the current certificate's DER encoding,
// colon-separated hex as browsers display it.
func (m *Manager) Fingerprint() string { return Fingerprint(m.Leaf()) }

// SPKIPin is the base64 SHA-256 of the current public key, the value curl's
// --pinnedpubkey sha256// and healthwatch compare against. Stable across
// renewals.
func (m *Manager) SPKIPin() string {
	pin, _ := SPKIPin(m.Leaf().PublicKey)
	return pin
}

// Refresh re-signs the certificate (same key) when it is within RenewBefore
// of expiry or its SANs no longer match Options.SANs. Reports whether a
// new certificate was issued. In operator-provided mode it never renews
// and only raises OnExpiring.
func (m *Manager) Refresh() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	leaf := m.Leaf()
	due := leaf.NotAfter.Sub(m.opts.Now()) < m.opts.RenewBefore
	if !m.opts.AutoManaged {
		if due && m.OnExpiring != nil {
			m.OnExpiring(leaf.NotAfter)
		}
		return false, nil
	}
	if !due && sameSANs(leaf, m.opts.SANs()) {
		return false, nil
	}
	key, ok := m.cur.Load().PrivateKey.(crypto.Signer)
	if !ok {
		return false, errors.New("apitls: private key is not a crypto.Signer")
	}
	if err := m.issue(key); err != nil {
		return false, err
	}
	slog.Info("apitls: certificate renewed", "fingerprint", m.Fingerprint(),
		"not_after", m.Leaf().NotAfter.Format(time.RFC3339), "spki_pin", m.SPKIPin())
	if m.OnRenewed != nil {
		m.OnRenewed(m.Fingerprint(), m.Leaf().NotAfter)
	}
	return true, nil
}

// Run calls Refresh every interval until ctx ends.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := m.Refresh(); err != nil {
				slog.Error("apitls: refresh failed", "err", err)
			}
		}
	}
}

// generate creates a new key and signs the first certificate with it.
func (m *Manager) generate() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("apitls: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("apitls: marshal key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(m.opts.KeyFile), 0o755); err != nil {
		return fmt.Errorf("apitls: mkdir: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeAtomic(m.opts.KeyFile, keyPEM, 0o600); err != nil {
		return err
	}
	if err := m.issue(key); err != nil {
		return err
	}
	slog.Info("apitls: generated self-signed certificate", "cert", m.opts.CertFile,
		"fingerprint", m.Fingerprint(), "not_after", m.Leaf().NotAfter.Format(time.RFC3339),
		"spki_pin", m.SPKIPin(), "sans", strings.Join(m.opts.SANs(), " "))
	return nil
}

// issue signs a certificate for key over the current SANs, writes it and
// swaps it in.
func (m *Manager) issue(key crypto.Signer) error {
	now := m.opts.Now()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return fmt.Errorf("apitls: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "turnout-gateway api", Organization: []string{"turnout-gateway"}},
		NotBefore:    now.Add(-5 * time.Minute), // tolerate clock skew on the client
		NotAfter:     now.Add(m.opts.Validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// CA:false with BasicConstraintsValid so an operator who imports
		// this certificate into a trust store has not trusted a signer.
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	for _, san := range m.opts.SANs() {
		if ip := net.ParseIP(san); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, san)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return fmt.Errorf("apitls: sign: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeAtomic(m.opts.CertFile, certPEM, 0o644); err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("apitls: parse issued certificate: %w", err)
	}
	m.cur.Store(&tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf})
	return nil
}

// sameSANs reports whether leaf covers exactly want (order-insensitive).
func sameSANs(leaf *x509.Certificate, want []string) bool {
	have := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	have = append(have, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		have = append(have, ip.String())
	}
	norm := func(in []string) []string {
		out := make([]string, 0, len(in))
		seen := map[string]bool{}
		for _, s := range in {
			if ip := net.ParseIP(s); ip != nil {
				s = ip.String()
			}
			if s == "" || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
		sort.Strings(out)
		return out
	}
	a, b := norm(have), norm(want)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("apitls: read %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("apitls: %s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apitls: %s: %w", path, err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("apitls: %s: key is not a signer", path)
	}
	return signer, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return fmt.Errorf("apitls: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, mode); err != nil { // WriteFile honours umask
		os.Remove(tmp)
		return fmt.Errorf("apitls: chmod %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("apitls: rename %s: %w", path, err)
	}
	return nil
}

// Fingerprint returns the SHA-256 of the certificate's DER as colon-separated
// uppercase hex — the format browsers show in the certificate viewer.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// SPKIPin returns base64(SHA-256(SubjectPublicKeyInfo DER)) — the value
// curl's --pinnedpubkey sha256//<pin> expects.
func SPKIPin(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("apitls: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:]), nil
}

// PinFromCertFile reads a PEM certificate and returns its SPKI pin. Used by
// callers on the node (healthwatch) that pin from the file the gateway
// wrote rather than from a configured value.
func PinFromCertFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("apitls: %s: no CERTIFICATE block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("apitls: %s: %w", path, err)
	}
	return SPKIPin(cert.PublicKey)
}

// VerifyPin returns a tls.Config.VerifyPeerCertificate that accepts any
// chain whose leaf public key hashes to pin, ignoring names and expiry.
// Pair it with InsecureSkipVerify=true: the pin is the whole trust decision.
func VerifyPin(pin string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("apitls: no peer certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return err
		}
		got, err := SPKIPin(leaf.PublicKey)
		if err != nil {
			return err
		}
		if got != pin {
			return fmt.Errorf("apitls: peer public key pin %s does not match expected %s", got, pin)
		}
		return nil
	}
}

// NodeSANs lists the names the auto-managed certificate should cover:
// loopback, the ingress address, every non-loopback IPv4 on the host, the
// hostname, plus extra. Duplicates and empties are dropped; order is
// stable so sameSANs comparisons do not churn.
func NodeSANs(ingressIP string, extra []string) []string {
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if ip := net.ParseIP(s); ip != nil {
			s = ip.String()
		}
		for _, have := range out {
			if have == s {
				return
			}
		}
		out = append(out, s)
	}
	add("127.0.0.1")
	add("::1")
	add("localhost")
	add(ingressIP)
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
				continue
			}
			add(ipn.IP.String())
		}
	}
	if h, err := os.Hostname(); err == nil {
		add(h)
	}
	for _, e := range extra {
		add(e)
	}
	return out
}
