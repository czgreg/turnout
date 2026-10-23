package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/mihomo"
)

// adBlockState is the GET/PUT shape. Missing is surfaced because its absence
// is the difference between "blocking" and "believing you are blocking": a
// missing rule-set makes mihomo log an error and keep serving with the rule
// matching nothing (verified against v1.19.26), so the switch would read as on
// while every ad still loads.
type adBlockState struct {
	Enabled          bool     `json:"enabled"`
	RuleSetInstalled bool     `json:"rule_set_installed"`
	Missing          []string `json:"missing,omitempty"`
}

// adBlockState stats every file the renderer will reference. mihomo.AdRuleSets
// is the single source of truth — duplicating the filenames here is how the two
// drift apart silently.
func (s *Server) adBlockState() adBlockState {
	var missing []string
	for _, rs := range mihomo.AdRuleSets {
		if _, err := os.Stat(filepath.Join(s.deps.Cfg.DataPlane.RuleSetsDir, rs.File)); err != nil {
			missing = append(missing, rs.File)
		}
	}
	return adBlockState{
		Enabled:          s.deps.Cfg.DataPlane.Route.AdBlock,
		RuleSetInstalled: len(missing) == 0,
		Missing:          missing,
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
		http.Error(w, "cannot enable ad blocking: missing "+strings.Join(state.Missing, ", ")+
			" — redeploy (scripts/stage.sh ships them) and retry", http.StatusConflict)
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