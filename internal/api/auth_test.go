package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/configstore"
)

const (
	tokA = "tgw_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	tokB = "tgw_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

type authFixture struct {
	t     *testing.T
	dir   string
	yaml  string
	cfg   *config.Config
	store *configstore.Store
	auth  *Auth
	h     http.Handler
}

// newAuthFixture loads a gateway.yaml (extra is appended under api:) with
// the token file in a temp dir, then builds the real server mux around it.
func newAuthFixture(t *testing.T, apiExtra string) *authFixture {
	t.Helper()
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "gateway.yaml")
	body := "api:\n  listen: \"127.0.0.1:18080\"\n  token_file: " + filepath.Join(dir, "api-token") + "\n" + apiExtra
	if err := os.WriteFile(yamlPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &authFixture{t: t, dir: dir, yaml: yamlPath}
	f.reload()
	return f
}

// reload simulates a process restart: re-read yaml, rebuild Auth + mux.
func (f *authFixture) reload() {
	f.t.Helper()
	cfg, err := config.Load(f.yaml)
	if err != nil {
		f.t.Fatal(err)
	}
	f.cfg = cfg
	f.store = configstore.New(f.yaml)
	a, err := NewAuth(AuthOptions{Cfg: cfg, Store: f.store, Fingerprint: "AA:BB"})
	if err != nil {
		f.t.Fatal(err)
	}
	f.auth = a
	f.h = NewServer(Deps{Cfg: cfg, Store: f.store, Auth: a}).srv.Handler
}

func (f *authFixture) do(method, path, token string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "10.1.3.77:5555"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *authFixture) code() string {
	f.t.Helper()
	data, err := os.ReadFile(f.auth.SetupCodePath())
	if err != nil {
		f.t.Fatalf("read setup code: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "setup_code="); ok {
			return v
		}
	}
	f.t.Fatalf("no setup_code line in %q", data)
	return ""
}

func errorOf(rec *httptest.ResponseRecorder) string {
	var body struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return body.Error
}

func TestSetupStateClosesEverything(t *testing.T) {
	f := newAuthFixture(t, "")

	if !f.auth.InSetup() {
		t.Fatal("no token anywhere must mean setup state")
	}
	rec := f.do("GET", "/api/status", "", nil)
	if rec.Code != http.StatusUnauthorized || errorOf(rec) != "setup_required" {
		t.Fatalf("GET /api/status in setup = %d %q, want 401 setup_required", rec.Code, rec.Body)
	}
	// Even a token-shaped header does not open anything in setup state.
	if rec := f.do("GET", "/api/auth/check", tokA, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("check in setup = %d, want 401", rec.Code)
	}

	rec = f.do("GET", "/api/auth/state", "", nil)
	var st AuthState
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if rec.Code != 200 || st.State != "setup" || st.SetupCodeHint != f.auth.SetupCodePath() {
		t.Fatalf("state = %d %+v", rec.Code, st)
	}
	if strings.Contains(rec.Body.String(), f.code()) {
		t.Fatal("GET /api/auth/state must never carry the setup code")
	}

	fi, err := os.Stat(f.auth.SetupCodePath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("setup code file mode = %o, want 600", fi.Mode().Perm())
	}
	data, _ := os.ReadFile(f.auth.SetupCodePath())
	if !strings.Contains(string(data), "tls_fingerprint_sha256=AA:BB") {
		t.Errorf("setup code file should carry the TLS fingerprint, got %q", data)
	}
	if len(normalizeCode(f.code())) != 20 {
		t.Errorf("setup code %q is not 20 base32 chars", f.code())
	}
}

func TestSetupFlow(t *testing.T) {
	f := newAuthFixture(t, "")
	code := f.code()

	if rec := f.do("POST", "/api/auth/setup", "", map[string]string{"token": tokA, "setup_code": "WRONG-CODE"}); rec.Code != http.StatusUnauthorized || errorOf(rec) != "invalid_setup_code" {
		t.Fatalf("wrong code = %d %q", rec.Code, rec.Body)
	}
	if rec := f.do("POST", "/api/auth/setup", "", map[string]string{"token": "short", "setup_code": code}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad token format = %d, want 400", rec.Code)
	}
	if rec := f.do("POST", "/api/auth/setup", "", map[string]any{"token": tokA, "setup_code": code, "extra": 1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", rec.Code)
	}
	// Lower-case, dash-free entry of the code is accepted.
	loose := strings.ToLower(strings.ReplaceAll(code, "-", ""))
	if rec := f.do("POST", "/api/auth/setup", "", map[string]string{"token": tokA, "setup_code": loose}); rec.Code != http.StatusNoContent {
		t.Fatalf("setup = %d %q, want 204", rec.Code, rec.Body)
	}

	fi, err := os.Stat(f.cfg.API.TokenPath())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %o, want 600", fi.Mode().Perm())
	}
	if _, err := os.Stat(f.auth.SetupCodePath()); !os.IsNotExist(err) {
		t.Error("setup code file must be deleted after setup")
	}
	if rec := f.do("GET", "/api/auth/check", tokA, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("check with new token = %d, want 204", rec.Code)
	}
	if rec := f.do("GET", "/api/auth/check", "", nil); rec.Code != http.StatusUnauthorized || errorOf(rec) != "unauthorized" {
		t.Fatalf("check without token = %d %q", rec.Code, rec.Body)
	}
	if rec := f.do("POST", "/api/auth/setup", "", map[string]string{"token": tokB, "setup_code": code}); rec.Code != http.StatusConflict {
		t.Fatalf("second setup = %d, want 409", rec.Code)
	}

	// Survives a restart from the file alone.
	f.reload()
	if f.auth.InSetup() || f.auth.Source() != TokenSourceFile {
		t.Fatalf("after restart: setup=%v source=%q", f.auth.InSetup(), f.auth.Source())
	}
	if rec := f.do("GET", "/api/auth/check", tokA, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("check after restart = %d", rec.Code)
	}
}

func TestConcurrentSetupHasOneWinner(t *testing.T) {
	f := newAuthFixture(t, "")
	code := f.code()
	var wg sync.WaitGroup
	results := make([]int, 16)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok := "tgw_" + strings.Repeat(string(rune('a'+i)), 43)
			results[i] = f.do("POST", "/api/auth/setup", "", map[string]string{"token": tok, "setup_code": code}).Code
		}(i)
	}
	wg.Wait()
	wins := 0
	for _, c := range results {
		switch c {
		case http.StatusNoContent:
			wins++
		case http.StatusConflict:
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if wins != 1 {
		t.Fatalf("%d setups succeeded, want exactly 1", wins)
	}
}

func TestRotate(t *testing.T) {
	f := newAuthFixture(t, "")
	f.do("POST", "/api/auth/setup", "", map[string]string{"token": tokA, "setup_code": f.code()})

	if rec := f.do("POST", "/api/auth/rotate", "", map[string]string{"token": tokB}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("rotate without token = %d, want 401", rec.Code)
	}
	if rec := f.do("POST", "/api/auth/rotate", tokA, map[string]string{"token": tokA}); rec.Code != http.StatusBadRequest {
		t.Fatalf("rotate to same token = %d, want 400", rec.Code)
	}
	if rec := f.do("POST", "/api/auth/rotate", tokA, map[string]string{"token": tokB}); rec.Code != http.StatusNoContent {
		t.Fatalf("rotate = %d %q", rec.Code, rec.Body)
	}
	if rec := f.do("GET", "/api/auth/check", tokA, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("old token after rotate = %d, want 401", rec.Code)
	}
	if rec := f.do("GET", "/api/auth/check", tokB, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("new token after rotate = %d, want 204", rec.Code)
	}
	data, _ := os.ReadFile(f.cfg.API.TokenPath())
	if strings.TrimSpace(string(data)) != tokB {
		t.Errorf("token file = %q, want the rotated token", data)
	}
}

func TestLegacyYAMLTokenThenRotateClearsIt(t *testing.T) {
	f := newAuthFixture(t, "  token: legacy-secret\n")
	if f.auth.InSetup() || f.auth.Source() != TokenSourceYAML {
		t.Fatalf("legacy token: setup=%v source=%q", f.auth.InSetup(), f.auth.Source())
	}
	if rec := f.do("GET", "/api/auth/check", "legacy-secret", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("legacy token check = %d", rec.Code)
	}
	if rec := f.do("POST", "/api/auth/rotate", "legacy-secret", map[string]string{"token": tokA}); rec.Code != http.StatusNoContent {
		t.Fatalf("rotate from legacy = %d %q", rec.Code, rec.Body)
	}
	if f.cfg.API.Token != "" {
		t.Error("rotation must clear api.token in memory")
	}
	onDisk, _ := os.ReadFile(f.yaml)
	if strings.Contains(string(onDisk), "legacy-secret") {
		t.Errorf("rotation must clear api.token in gateway.yaml, got:\n%s", onDisk)
	}
	f.reload()
	if f.auth.Source() != TokenSourceFile {
		t.Fatalf("after restart source = %q, want file", f.auth.Source())
	}
}

func TestTokenFileWinsOverYAML(t *testing.T) {
	f := newAuthFixture(t, "  token: legacy-secret\n")
	if err := os.WriteFile(f.cfg.API.TokenPath(), []byte(tokA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.reload()
	if f.auth.Source() != TokenSourceFile {
		t.Fatalf("source = %q, want file", f.auth.Source())
	}
	if rec := f.do("GET", "/api/auth/check", "legacy-secret", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("yaml token must not work when the file is present: %d", rec.Code)
	}
}

func TestMalformedTokenFileFailsStartup(t *testing.T) {
	f := newAuthFixture(t, "")
	if err := os.WriteFile(f.cfg.API.TokenPath(), []byte("not-a-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAuth(AuthOptions{Cfg: f.cfg, Store: f.store}); err == nil {
		t.Fatal("a garbled token file must stop startup, not silently enter setup")
	}
}

func TestResetTokenReturnsToSetup(t *testing.T) {
	f := newAuthFixture(t, "  token: legacy-secret\n")
	if err := os.WriteFile(f.cfg.API.TokenPath(), []byte(tokA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ResetToken(f.cfg, f.store); err != nil {
		t.Fatal(err)
	}
	f.reload()
	if !f.auth.InSetup() {
		t.Fatal("after reset the node must start in setup state")
	}
	onDisk, _ := os.ReadFile(f.yaml)
	if strings.Contains(string(onDisk), "legacy-secret") {
		t.Error("reset must clear the legacy yaml token")
	}
}

func TestRepeatedFailuresAlertOncePerWindow(t *testing.T) {
	f := newAuthFixture(t, "")
	f.do("POST", "/api/auth/setup", "", map[string]string{"token": tokA, "setup_code": f.code()})
	for i := 0; i < failAlertAt-1; i++ {
		f.do("GET", "/api/auth/check", tokB, nil)
	}
	if _, ok := f.auth.alerted["10.1.3.77"]; ok {
		t.Fatal("alerted before the threshold")
	}
	f.do("GET", "/api/auth/check", tokB, nil)
	first, ok := f.auth.alerted["10.1.3.77"]
	if !ok {
		t.Fatal("no alert at the threshold")
	}
	f.do("GET", "/api/auth/check", tokB, nil)
	if f.auth.alerted["10.1.3.77"] != first {
		t.Error("alert must fire once per window, not per failure")
	}
}

func TestAuthBodyIsCapped(t *testing.T) {
	f := newAuthFixture(t, "")
	big := map[string]string{"token": tokA, "setup_code": strings.Repeat("A", authBodyLimit)}
	if rec := f.do("POST", "/api/auth/setup", "", big); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d, want 400", rec.Code)
	}
	if !f.auth.InSetup() {
		t.Fatal("oversized body must not complete setup")
	}
}
