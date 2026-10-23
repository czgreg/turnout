package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

func adBlockServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.DataPlane.RuleSetsDir = dir
	return &Server{deps: Deps{Cfg: cfg}}, dir
}

func putAdBlock(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/ad-block", strings.NewReader(body))
	s.handleAdBlockPut(rec, req)
	return rec
}

// A missing .mrs does not stop mihomo — it logs and keeps serving with the
// rule matching nothing. Enabling in that state would look identical to
// working, so the handler must refuse.
func TestAdBlockPut_RefusesWhenRuleSetMissing(t *testing.T) {
	s, _ := adBlockServer(t)
	rec := putAdBlock(t, s, `{"enabled":true}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if s.deps.Cfg.DataPlane.Route.AdBlock {
		t.Error("cfg must not be mutated when the rule-set is missing")
	}
}

func TestAdBlockGet_ReportsInstalledRuleSet(t *testing.T) {
	s, dir := adBlockServer(t)

	get := func() string {
		rec := httptest.NewRecorder()
		s.handleAdBlockGet(rec, httptest.NewRequest(http.MethodGet, "/api/ad-block", nil))
		return rec.Body.String()
	}

	if got := get(); !strings.Contains(got, `"rule_set_installed":false`) {
		t.Fatalf("expected rule_set_installed=false, got %s", got)
	}

	if err := os.WriteFile(filepath.Join(dir, adsRuleSetFile), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := get(); !strings.Contains(got, `"rule_set_installed":true`) {
		t.Fatalf("expected rule_set_installed=true, got %s", got)
	}
}

// Turning it off when it is already off must not touch the store or trigger a
// reload — the console polls this endpoint on every page load.
func TestAdBlockPut_NoOpWhenUnchanged(t *testing.T) {
	s, _ := adBlockServer(t)
	rec := putAdBlock(t, s, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("unexpected error body: %s", rec.Body.String())
	}
}

func TestAdBlockPut_RequiresEnabledField(t *testing.T) {
	s, _ := adBlockServer(t)
	if rec := putAdBlock(t, s, `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
