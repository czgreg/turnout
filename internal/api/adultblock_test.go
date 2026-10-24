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

func adultBlockServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{}
	cfg.DataPlane.RuleSetsDir = dir
	return &Server{deps: Deps{Cfg: cfg}}, dir
}

func putAdultBlock(t *testing.T, s *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/adult-block", strings.NewReader(body))
	s.handleAdultBlockPut(rec, req)
	return rec
}

// writeAdultRuleSets creates every file adult blocking depends on, except `skip`.
func writeAdultRuleSets(t *testing.T, dir, skip string) {
	t.Helper()
	for _, rs := range mihomo.AdultRuleSets {
		if rs.File == skip {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, rs.File), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Same silent-failure class as ad blocking: mihomo logs "no such file" and
// keeps serving with the rule matching nothing, so enabling in that state
// would look identical to working.
func TestAdultBlockPut_RefusesWhenRuleSetMissing(t *testing.T) {
	for _, rs := range mihomo.AdultRuleSets {
		t.Run(rs.File, func(t *testing.T) {
			s, dir := adultBlockServer(t)
			writeAdultRuleSets(t, dir, rs.File)

			rec := putAdultBlock(t, s, `{"enabled":true}`)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), rs.File) {
				t.Errorf("409 body must name the missing file %q, got %s", rs.File, rec.Body.String())
			}
			if s.deps.Cfg.DataPlane.Route.AdultBlock {
				t.Error("cfg must not be mutated when a rule-set is missing")
			}
		})
	}
}

func TestAdultBlockGet_ReportsInstalledRuleSetsAndAllow(t *testing.T) {
	s, dir := adultBlockServer(t)
	s.deps.Cfg.DataPlane.Route.AdultBlockAllow = config.StringList{"example-health.org"}

	get := func() string {
		rec := httptest.NewRecorder()
		s.handleAdultBlockGet(rec, httptest.NewRequest(http.MethodGet, "/api/adult-block", nil))
		return rec.Body.String()
	}

	got := get()
	if !strings.Contains(got, `"rule_set_installed":false`) {
		t.Fatalf("expected rule_set_installed=false, got %s", got)
	}
	for _, rs := range mihomo.AdultRuleSets {
		if !strings.Contains(got, `"`+rs.File+`"`) {
			t.Errorf("missing list must name %q, got %s", rs.File, got)
		}
	}
	if !strings.Contains(got, `"allow":["example-health.org"]`) {
		t.Errorf("allow list not surfaced, got %s", got)
	}

	writeAdultRuleSets(t, dir, "")
	if got := get(); !strings.Contains(got, `"rule_set_installed":true`) {
		t.Fatalf("expected rule_set_installed=true, got %s", got)
	}

	if err := os.Remove(filepath.Join(dir, mihomo.AdultRuleSets[1].File)); err != nil {
		t.Fatal(err)
	}
	got = get()
	if !strings.Contains(got, `"rule_set_installed":false`) {
		t.Fatalf("expected rule_set_installed=false after removing one file, got %s", got)
	}
	if !strings.Contains(got, `"`+mihomo.AdultRuleSets[1].File+`"`) {
		t.Errorf("expected the removed file in missing, got %s", got)
	}
}

// GET must never emit null for allow — the console renders the editor
// without a null check.
func TestAdultBlockGet_AllowIsNeverNull(t *testing.T) {
	s, _ := adultBlockServer(t)
	rec := httptest.NewRecorder()
	s.handleAdultBlockGet(rec, httptest.NewRequest(http.MethodGet, "/api/adult-block", nil))
	if !strings.Contains(rec.Body.String(), `"allow":[]`) {
		t.Fatalf("allow must be [], got %s", rec.Body.String())
	}
}

// Turning it off when it is already off must not touch the store or trigger
// a reload — the console polls this endpoint on every page load.
func TestAdultBlockPut_NoOpWhenUnchanged(t *testing.T) {
	s, _ := adultBlockServer(t)
	rec := putAdultBlock(t, s, `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdultBlockPut_RequiresEnabledField(t *testing.T) {
	s, _ := adultBlockServer(t)
	if rec := putAdultBlock(t, s, `{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAdultBlockPut_RejectsInvalidAllowEntry(t *testing.T) {
	s, _ := adultBlockServer(t)
	for _, body := range []string{
		`{"enabled":false,"allow":["https://example.com"]}`,
		`{"enabled":false,"allow":["not a domain"]}`,
		`{"enabled":false,"allow":["nodot"]}`,
	} {
		rec := putAdultBlock(t, s, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400; resp=%s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestNormalizeAdultAllow(t *testing.T) {
	in := []string{" +.Example.ORG ", "*.example.net", ".example.io", "example.org", ""}
	got, err := normalizeAdultAllow(&in)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.org", "example.net", "example.io"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if got, err := normalizeAdultAllow(nil); got != nil || err != nil {
		t.Fatalf("nil input must stay nil, got %v, %v", got, err)
	}
}
