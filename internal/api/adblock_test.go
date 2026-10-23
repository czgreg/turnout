package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/mihomo"
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

// writeAdRuleSets creates every file ad blocking depends on, except `skip`.
func writeAdRuleSets(t *testing.T, dir, skip string) {
	t.Helper()
	for _, rs := range mihomo.AdRuleSets {
		if rs.File == skip {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, rs.File), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A missing rule-set does not stop mihomo — it logs and keeps serving with the
// rule matching nothing. Enabling in that state would look identical to
// working, so the handler must refuse, and it must name which file is missing.
func TestAdBlockPut_RefusesWhenRuleSetMissing(t *testing.T) {
	for _, rs := range mihomo.AdRuleSets {
		t.Run(rs.File, func(t *testing.T) {
			s, dir := adBlockServer(t)
			writeAdRuleSets(t, dir, rs.File)

			rec := putAdBlock(t, s, `{"enabled":true}`)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), rs.File) {
				t.Errorf("409 body must name the missing file %q, got %s", rs.File, rec.Body.String())
			}
			if s.deps.Cfg.DataPlane.Route.AdBlock {
				t.Error("cfg must not be mutated when a rule-set is missing")
			}
		})
	}
}

func TestAdBlockGet_ReportsInstalledRuleSets(t *testing.T) {
	s, dir := adBlockServer(t)

	get := func() string {
		rec := httptest.NewRecorder()
		s.handleAdBlockGet(rec, httptest.NewRequest(http.MethodGet, "/api/ad-block", nil))
		return rec.Body.String()
	}

	// Nothing on disk: every file must be reported, not just the first.
	got := get()
	if !strings.Contains(got, `"rule_set_installed":false`) {
		t.Fatalf("expected rule_set_installed=false, got %s", got)
	}
	for _, rs := range mihomo.AdRuleSets {
		if !strings.Contains(got, `"`+rs.File+`"`) {
			t.Errorf("missing list must name %q, got %s", rs.File, got)
		}
	}

	writeAdRuleSets(t, dir, "")
	if got := get(); !strings.Contains(got, `"rule_set_installed":true`) {
		t.Fatalf("expected rule_set_installed=true, got %s", got)
	}

	// Removing one file flips the state back and reports exactly that one.
	if err := os.Remove(filepath.Join(dir, mihomo.AdRuleSets[1].File)); err != nil {
		t.Fatal(err)
	}
	got = get()
	if !strings.Contains(got, `"rule_set_installed":false`) {
		t.Fatalf("expected rule_set_installed=false after removing one file, got %s", got)
	}
	if !strings.Contains(got, `"`+mihomo.AdRuleSets[1].File+`"`) {
		t.Errorf("expected the removed file in missing, got %s", got)
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
