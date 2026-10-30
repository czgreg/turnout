package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/apitls"
)

// healthwatch talks to the gateway's self-signed HTTPS API by pinning the
// public key in the certificate file the gateway wrote. A matching file must
// connect; a certificate from a different key must not.
func TestPinAPI(t *testing.T) {
	newMgr := func(dir string) *apitls.Manager {
		m, err := apitls.New(apitls.Options{
			CertFile:    filepath.Join(dir, "cert.pem"),
			KeyFile:     filepath.Join(dir, "key.pem"),
			AutoManaged: true,
			SANs:        func() []string { return []string{"127.0.0.1"} },
		})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	serverDir, otherDir := t.TempDir(), t.TempDir()
	srvMgr := newMgr(serverDir)
	newMgr(otherDir)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvMgr.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})}
	go srv.Serve(ln)
	defer srv.Close()
	base := "https://" + ln.Addr().(*net.TCPAddr).String()

	saved := httpClient.Transport
	t.Cleanup(func() { httpClient.Transport = saved })

	if err := pinAPI(filepath.Join(serverDir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	var out struct{ OK bool }
	if code, _, err := getJSON(context.Background(), base, "/healthz", &out, ""); err != nil || code != 200 || !out.OK {
		t.Fatalf("pinned to the right key: code=%d err=%v out=%+v", code, err, out)
	}

	if err := pinAPI(filepath.Join(otherDir, "cert.pem")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := getJSON(context.Background(), base, "/healthz", nil, ""); err == nil {
		t.Fatal("pinned to a different key: request must fail")
	}
}
