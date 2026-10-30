package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/apitls"
)

// startMux serves a tiny handler behind the TLS mux on a random port and
// returns its address plus the pin to verify it with.
func startMux(t *testing.T) (addr string, pin string) {
	t.Helper()
	dir := t.TempDir()
	m, err := apitls.New(apitls.Options{
		CertFile:    filepath.Join(dir, "cert.pem"),
		KeyFile:     filepath.Join(dir, "key.pem"),
		AutoManaged: true,
		SANs:        func() []string { return []string{"127.0.0.1"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inner.Close()
	addr = inner.Addr().String()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			t.Errorf("handler saw a non-TLS request %s %s", r.Method, r.URL)
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveTLS(ctx, srv, addr, m.TLSConfig()) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serveTLS: %v", err)
		}
	})
	// Wait for the port to accept.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return addr, m.SPKIPin()
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return "", ""
}

func rawRequest(t *testing.T, addr, req string) *http.Response {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(c, req); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	return resp
}

func TestTLSMuxServesHTTPS(t *testing.T) {
	addr, pin := startMux(t)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: apitls.VerifyPin(pin),
	}}}
	resp, err := client.Get("https://" + addr + "/api/status")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
}

func TestTLSMuxRedirectsPlaintextGET(t *testing.T) {
	addr, _ := startMux(t)
	resp := rawRequest(t, addr, "GET /ui/?x=1 HTTP/1.1\r\nHost: node.example:18080\r\n\r\n")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("status = %d, want 308", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "https://node.example:18080/ui/?x=1" {
		t.Errorf("Location = %q", loc)
	}
	resp = rawRequest(t, addr, "HEAD /ui/ HTTP/1.1\r\nHost: n\r\n\r\n")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("HEAD status = %d, want 308", resp.StatusCode)
	}
}

func TestTLSMuxRefusesPlaintextMutations(t *testing.T) {
	addr, _ := startMux(t)
	resp := rawRequest(t, addr, "PUT /api/whitelist HTTP/1.1\r\nHost: n\r\nAuthorization: Bearer x\r\nContent-Length: 2\r\n\r\n{}")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "" {
		t.Error("mutating plaintext request must not be redirected")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "rotate") {
		t.Errorf("body should tell the operator to rotate the token, got %q", body)
	}
}

func TestTLSMuxRejectsGarbage(t *testing.T) {
	addr, _ := startMux(t)
	resp := rawRequest(t, addr, "\x00\x01not http at all\r\n\r\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestTLSMuxDropsSilentConnection(t *testing.T) {
	addr, pin := startMux(t)
	silent, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	// A connection that never sends must not block the next one.
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: apitls.VerifyPin(pin),
	}}}
	if _, err := client.Get("https://" + addr + "/"); err != nil {
		t.Fatalf("second connection blocked by a silent first one: %v", err)
	}
}
