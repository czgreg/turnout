package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		RuleLists:    []config.RuleListConfig{{Tag: "gemini", URL: "https://yfamilys.com/rule/Gemini.list"}},
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
	if len(p.RuleLists) != 1 || p.RuleLists[0].Tag != "gemini" {
		t.Errorf("rule_lists = %v", p.RuleLists)
	}
	// The console reads l.tag / l.url; Go's default field names would be
	// "Tag"/"URL" and silently render as undefined.
	for _, want := range []string{`"tag":"gemini"`, `"url":"https://yfamilys.com/rule/Gemini.list"`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("body missing %s: %s", want, rec.Body.String())
		}
	}
}
