package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/configstore"
	"github.com/turnout-gateway/turnout-gateway/internal/xborder"
)

// Deliberately unusual subscription entries: per-entry UA, a disabled one,
// an explicit format. Any normalization on write-back would show up here.
const xbSubs = `subscriptions:
  - name: sub-b
    url: "https://b.example/api/v1/client/subscribe?token=SECRET-B"
    format: clash
    enabled: true
    user_agent: "clash-verge/v2.0.0"
  - name: sub-a
    url: "https://a.example/sub?x=1&token=SECRET-A"
    format: auto
    enabled: false
`

type xbFixture struct {
	t    *testing.T
	yaml string
	cfg  *config.Config
	mgr  *xborder.Manager
	h    http.Handler
}

func newXBFixture(t *testing.T, extra string) *xbFixture {
	t.Helper()
	dir := t.TempDir()
	tokPath := filepath.Join(dir, "api-token")
	if err := os.WriteFile(tokPath, []byte(tokA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "gateway.yaml")
	body := "api:\n  listen: \"127.0.0.1:18080\"\n  token_file: " + tokPath + "\n" + xbSubs + extra
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	store := configstore.New(p)
	a, err := NewAuth(AuthOptions{Cfg: cfg, Store: store, Fingerprint: "AA:BB"})
	if err != nil {
		t.Fatal(err)
	}
	// mihomo is not running in tests: the collector's samples fail and it
	// logs a warning, which is what a node with mihomo down would do too.
	mgr := xborder.NewManager(xborder.Options{APIAddr: "127.0.0.1:1", Hostname: "gw-test"})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		mgr.Apply(config.XBorderLogConfig{}) // stop goroutines before TempDir cleanup
	})
	if err := mgr.Start(ctx, cfg.XBorderLog); err != nil {
		t.Fatal(err)
	}
	f := &xbFixture{t: t, yaml: p, cfg: cfg, mgr: mgr}
	f.h = NewServer(Deps{Cfg: cfg, Store: store, Auth: a, XBorder: mgr}).srv.Handler
	return f
}

func (f *xbFixture) do(method string, body any) (int, XBorderLogView, string) {
	f.t.Helper()
	af := &authFixture{t: f.t, h: f.h}
	rec := af.do(method, "/api/xborder-log", tokA, body)
	var v XBorderLogView
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			f.t.Fatalf("decode: %v: %s", err, rec.Body)
		}
	}
	return rec.Code, v, rec.Body.String()
}

func subsOnDisk(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Subscriptions []map[string]any `yaml:"subscriptions"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Subscriptions
}

func syslogListener(t *testing.T) (string, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	lines := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					lines <- sc.Text()
				}
			}()
		}
	}()
	return ln.Addr().String(), lines
}

func TestXBorderLogGetShowsDefaultsWhileDisabled(t *testing.T) {
	f := newXBFixture(t, "")
	code, v, body := f.do("GET", nil)
	if code != http.StatusOK {
		t.Fatalf("GET = %d %s", code, body)
	}
	want := XBorderLogSettings{Framing: "lf", Facility: "local5", AppName: "turnout-xborder", PollIntervalMs: 1000, QueueSize: 10000}
	if v.Config != want {
		t.Errorf("config = %+v, want %+v", v.Config, want)
	}
	if v.Status.Running || v.DataPlaneLogLevel != "info" {
		t.Errorf("status/log level = %+v %q", v.Status, v.DataPlaneLogLevel)
	}
}

// The hard rule from CLAUDE.md: saving this setting must not touch
// subscriptions[] — not the order, not the URL, not the UA.
func TestXBorderLogPutLeavesSubscriptionsAlone(t *testing.T) {
	f := newXBFixture(t, "")
	before := subsOnDisk(t, f.yaml)
	addr, lines := syslogListener(t)

	code, v, body := f.do("PUT", map[string]any{"enabled": true, "address": addr})
	if code != http.StatusOK {
		t.Fatalf("PUT = %d %s", code, body)
	}
	if !v.Config.Enabled || v.Config.Address != addr || !v.Status.Running {
		t.Errorf("view = %+v", v)
	}
	if after := subsOnDisk(t, f.yaml); !reflect.DeepEqual(before, after) {
		t.Errorf("subscriptions changed on write-back:\nbefore %v\nafter  %v", before, after)
	}
	if !reflect.DeepEqual(before[0]["url"], "https://b.example/api/v1/client/subscribe?token=SECRET-B") {
		t.Errorf("fixture sanity: %v", before)
	}

	// The written file must load and carry the block.
	cfg, err := config.Load(f.yaml)
	if err != nil {
		t.Fatalf("written yaml does not load: %v", err)
	}
	if !cfg.XBorderLog.Enabled || cfg.XBorderLog.Address != addr {
		t.Errorf("persisted = %+v", cfg.XBorderLog)
	}
	_ = lines
}

func TestXBorderLogPutValidation(t *testing.T) {
	f := newXBFixture(t, "")
	before, _ := os.ReadFile(f.yaml)
	for name, body := range map[string]map[string]any{
		"enable without address": {"enabled": true},
		"address without port":   {"enabled": true, "address": "192.0.2.50"},
		"bad port":               {"enabled": true, "address": "192.0.2.50:70000"},
		"bad facility":           {"enabled": true, "address": "192.0.2.50:514", "facility": "user"},
		"poll too fast":          {"enabled": true, "address": "192.0.2.50:514", "poll_interval_ms": 50},
		"unknown field":          {"enabled": true, "address": "192.0.2.50:514", "tls": true},
	} {
		code, _, msg := f.do("PUT", body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: code %d %s, want 400", name, code, msg)
		}
	}
	if after, _ := os.ReadFile(f.yaml); string(after) != string(before) {
		t.Error("a rejected PUT must not write gateway.yaml")
	}
	if f.cfg.XBorderLog.Enabled || f.cfg.XBorderLog.Address != "" {
		t.Errorf("a rejected PUT must not change the in-memory config: %+v", f.cfg.XBorderLog)
	}
}

func TestXBorderLogPutRejectsWhenMihomoLogLevelTooHigh(t *testing.T) {
	f := newXBFixture(t, "data_plane:\n  log_level: warning\n")
	code, _, msg := f.do("PUT", map[string]any{"enabled": true, "address": "192.0.2.50:514"})
	if code != http.StatusBadRequest || !strings.Contains(msg, "log_level") {
		t.Errorf("code %d %q, want 400 naming log_level", code, msg)
	}
}

// Changing the address applies without a restart: the sink reconnects to
// the new server, and disabling stops it.
func TestXBorderLogHotSwap(t *testing.T) {
	f := newXBFixture(t, "")
	addr1, _ := syslogListener(t)
	addr2, _ := syslogListener(t)

	if code, _, b := f.do("PUT", map[string]any{"enabled": true, "address": addr1}); code != 200 {
		t.Fatalf("enable: %d %s", code, b)
	}
	waitConnected(t, f.mgr, true)

	code, v, b := f.do("PUT", map[string]any{"address": addr2, "framing": "octet-counting"})
	if code != 200 || v.Config.Address != addr2 || v.Config.Framing != "octet-counting" || !v.Config.Enabled {
		t.Fatalf("swap: %d %+v %s", code, v.Config, b)
	}
	waitConnected(t, f.mgr, true)

	code, v, _ = f.do("PUT", map[string]any{"enabled": false})
	if code != 200 || v.Config.Enabled || v.Status.Running {
		t.Fatalf("disable: %d %+v", code, v)
	}
	if v.Config.Address != addr2 {
		t.Errorf("disabling must keep the address for next time, got %q", v.Config.Address)
	}
}

func waitConnected(t *testing.T, m *xborder.Manager, want bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m.Status().Connected == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connected never became %v: %+v", want, m.Status())
}

func TestXBorderLogNeedsAuth(t *testing.T) {
	f := newXBFixture(t, "")
	af := &authFixture{t: t, h: f.h}
	if rec := af.do("GET", "/api/xborder-log", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET without token = %d", rec.Code)
	}
	if rec := af.do("PUT", "/api/xborder-log", "", map[string]any{"enabled": false}); rec.Code != http.StatusUnauthorized {
		t.Errorf("PUT without token = %d", rec.Code)
	}
}
