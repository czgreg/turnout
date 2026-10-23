package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

func TestPoolsGet(t *testing.T) {
	perTerm := true
	s := &Server{deps: Deps{Cfg: &config.Config{Pools: []config.PoolConfig{{
		Name:         "ai-pool",
		NodePattern:  `momo/.*(香港|新加坡)`,
		Size:         4,
		PerTerminal:  &perTerm,
		RuleSets:     []string{"geosite-openai", "geosite-anthropic"},
		DomainSuffix: []string{"gemini.google.com"},
	}}}}}

	rec := httptest.NewRecorder()
	s.handlePoolsGet(rec, httptest.NewRequest(http.MethodGet, "/api/pools", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got []poolConfigDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("pools = %d, want 1", len(got))
	}
	p := got[0]
	if p.Name != "ai-pool" || p.NodePattern != `momo/.*(香港|新加坡)` || p.Size != 4 || !p.PerTerminal {
		t.Errorf("pool = %+v", p)
	}
	if len(p.RuleSets) != 2 || p.RuleSets[0] != "geosite-openai" {
		t.Errorf("rule_sets = %v", p.RuleSets)
	}
	if len(p.DomainSuffix) != 1 || p.DomainSuffix[0] != "gemini.google.com" {
		t.Errorf("domain_suffix = %v", p.DomainSuffix)
	}
}
