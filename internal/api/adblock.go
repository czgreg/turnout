package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// adsRuleSetFile must match internal/mihomo's rsAdsAll tag + ".mrs": the
// renderer emits `RULE-SET,category-ads-all,REJECT` and resolves the provider
// path as <RuleSetsDir>/<tag>.mrs.
const adsRuleSetFile = "category-ads-all.mrs"

// adBlockState is the GET/PUT shape. RuleSetInstalled is surfaced because it
// is the difference between "blocking" and "believing you are blocking": a
// missing .mrs makes mihomo log an error and keep running with the rule
// matching nothing (verified against v1.19.26), so the switch would read as
// on while every ad still loads.
type adBlockState struct {
	Enabled          bool `json:"enabled"`
	RuleSetInstalled bool `json:"rule_set_installed"`
}

func (s *Server) adBlockState() adBlockState {
	_, err := os.Stat(filepath.Join(s.deps.Cfg.DataPlane.RuleSetsDir, adsRuleSetFile))
	return adBlockState{
		Enabled:          s.deps.Cfg.DataPlane.Route.AdBlock,
		RuleSetInstalled: err == nil,
	}
}

func (s *Server) handleAdBlockGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.adBlockState())
}

// handleAdBlockPut flips the switch. Applies by re-rendering and hot-reloading
// mihomo — no restart, no rule-set download (stage.sh ships the file).
func (s *Server) handleAdBlockPut(w http.ResponseWriter, r *http.Request) {
	var dto struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dto.Enabled == nil {
		http.Error(w, "enabled field is required", http.StatusBadRequest)
		return
	}

	state := s.adBlockState()
	if *dto.Enabled && !state.RuleSetInstalled {
		http.Error(w, "cannot enable ad blocking: "+adsRuleSetFile+
			" is not on disk — redeploy (scripts/stage.sh ships it) and retry", http.StatusConflict)
		return
	}
	if *dto.Enabled == state.Enabled {
		writeJSON(w, http.StatusOK, state)
		return
	}

	if err := s.deps.Store.Mutate(s.deps.Cfg, func(c *config.Config) error {
		c.DataPlane.Route.AdBlock = *dto.Enabled
		return nil
	}); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// WithoutCancel: the switch is already persisted, so a client disconnect
	// must not leave mihomo routing by the previous value. Same reasoning as
	// PUT /api/whitelist.
	if err := s.rerenderAndReload(context.WithoutCancel(r.Context())); err != nil {
		http.Error(w, "reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.adBlockState())
}