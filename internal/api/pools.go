package api

import "net/http"

// poolConfigDTO is the read-only view of one named pool from gateway.yaml.
// The console uses it to show which groups exist and which rule sets each
// one claims. Pools are operator-owned yaml; there is no PUT endpoint.
type poolConfigDTO struct {
	Name            string   `json:"name"`
	NodePattern     string   `json:"node_pattern"`
	Size            int      `json:"size"`
	PerTerminal     bool     `json:"per_terminal"`
	RequiresPassing []string `json:"requires_passing,omitempty"`
	RuleSets        []string `json:"rule_sets,omitempty"`
	DomainSuffix    []string `json:"domain_suffix,omitempty"`
}

// handlePoolsGet answers GET /api/pools: the configured class pools, without
// their live members. Members come from /api/proxies/active (pools[].nodes),
// which the console joins by pool name.
func (s *Server) handlePoolsGet(w http.ResponseWriter, _ *http.Request) {
	out := make([]poolConfigDTO, 0, len(s.deps.Cfg.Pools))
	for _, p := range s.deps.Cfg.Pools {
		out = append(out, poolConfigDTO{
			Name:            p.Name,
			NodePattern:     p.NodePattern,
			Size:            p.Size,
			PerTerminal:     p.PerTerminalEnabled(),
			RequiresPassing: append([]string{}, p.RequiresPassing...),
			RuleSets:        append([]string{}, p.RuleSets...),
			DomainSuffix:    append([]string{}, p.DomainSuffix...),
		})
	}
	writeJSON(w, http.StatusOK, out)
}
