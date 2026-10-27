package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/nodescorer"
	"github.com/turnout-gateway/turnout-gateway/internal/subscribe"
)

// terminalFakeRenderer returns a fixed default (Asia) and class (US)
// assignment, so the handler's DTO wiring can be checked without mihomo.
type terminalFakeRenderer struct {
	blockingRenderer
}

func (f *terminalFakeRenderer) AssignmentForIP(_ string, _ []subscribe.Outbound) ([]string, bool) {
	return []string{"asia1", "asia2"}, true
}

func (f *terminalFakeRenderer) PoolAssignmentForIP(_ string, pool string, _ []subscribe.Outbound) ([]string, bool) {
	if pool != "ai-pool" {
		return nil, false
	}
	return []string{"us1", "us2"}, true
}

func (f *terminalFakeRenderer) RenderWithPools(_ []subscribe.Outbound, _, _ []string, _ map[string][]string, _ map[string]map[string][]string) ([]byte, error) {
	return []byte("rendered"), nil
}

// TestPoolTerminal_ReportsClassPools verifies the per-class egress block on
// /api/pool/terminal: the default class stays in primary/secondary and each
// per_terminal class pool gets its own entry with the fb-<pool>-* group name.
func TestPoolTerminal_ReportsClassPools(t *testing.T) {
	rend := &terminalFakeRenderer{}
	scorer := nodescorer.New(
		config.NodeQualifyConfig{}, nil, "127.0.0.1:0", "", "http://test", "",
		rend, func() []subscribe.Outbound { return nil },
	)
	cfg := &config.Config{
		Node: config.NodeConfig{ClientSubnet: "10.1.2.0/24"},
		Pools: []config.PoolConfig{{
			Name:        "ai-pool",
			PerTerminal: poolBoolAPI(true),
		}},
	}
	s := &Server{deps: Deps{
		Cfg:        cfg,
		Subscribe:  subscribe.NewManagerWithFetch(nil, time.Second, "test-ua"),
		Renderer:   rend,
		NodeScorer: scorer,
	}}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/pool/terminal?ip=10.1.2.42", nil)
	s.handlePoolTerminal(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got TerminalAssignment
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Pools) != 1 {
		t.Fatalf("pools = %+v, want exactly one class pool", got.Pools)
	}
	p := got.Pools[0]
	if p.Pool != "ai-pool" {
		t.Errorf("pool = %q, want ai-pool", p.Pool)
	}
	if !strings.HasPrefix(p.GroupName, "fb-ai-pool-p-") {
		t.Errorf("group_name = %q, want an fb-ai-pool-p-<pair> group", p.GroupName)
	}
	if p.Primary == nil || p.Primary.Name != "us1" {
		t.Errorf("primary = %+v, want us1", p.Primary)
	}
	if p.Secondary == nil || p.Secondary.Name != "us2" {
		t.Errorf("secondary = %+v, want us2", p.Secondary)
	}
}

func poolBoolAPI(b bool) *bool { return &b }
