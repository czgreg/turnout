package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/mihomo"
)

// adultBlockState is the GET/PUT shape. RuleSetInstalled is the difference
// between "blocking" and "believing you are blocking": a missing file makes
// mihomo log an error and keep serving with the rule matching nothing.
//
// Allow is always present (empty slice, not null) so the console can render
// the editor without a null check.
type adultBlockState struct {
	Enabled          bool     `json:"enabled"`
	RuleSetInstalled bool     `json:"rule_set_installed"`
	Missing          []string `json:"missing,omitempty"`
	Allow            []string `json:"allow"`
}

// adultBlockState stats every file the renderer will reference.
// mihomo.AdultRuleSets is the single source of truth — duplicating filenames
// here is how the two drift apart silently.
func (s *Server) adultBlockState() adultBlockState {
	var missing []string
	for _, rs := range mihomo.AdultRuleSets {
		if _, err := os.Stat(filepath.Join(s.deps.Cfg.DataPlane.RuleSetsDir, rs.File)); err != nil {
			missing = append(missing, rs.File)
		}
	}
	allow := append([]string(nil), s.deps.Cfg.DataPlane.Route.AdultBlockAllow...)
	if allow == nil {
		allow = []string{}
	}
	return adultBlockState{
		Enabled:          s.deps.Cfg.DataPlane.Route.AdultBlock,
		RuleSetInstalled: len(missing) == 0,
		Missing:          missing,
		Allow:            allow,
	}
}

func (s *Server) handleAdultBlockGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.adultBlockState())
}

// handleAdultBlockPut flips the switch and (optionally) replaces the
// exemption list. Applies by re-rendering and hot-reloading mihomo — no
// restart, no rule-set download (stage.sh ships the files).
//
// `allow` is optional: omitting it leaves the stored list untouched. An
// explicit [] clears it. That distinction matters because the switch and the
// list are edited from the same card, and a bare {"enabled":true} must not
// wipe exemptions the operator set earlier.
func (s *Server) handleAdultBlockPut(w http.ResponseWriter, r *http.Request) {
	var dto struct {
		Enabled *bool     `json:"enabled"`
		Allow   *[]string `json:"allow"`
	}
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dto.Enabled == nil {
		http.Error(w, "enabled field is required", http.StatusBadRequest)
		return
	}

	allow, err := normalizeAdultAllow(dto.Allow)
	if err != nil {
		http.Error(w, "invalid allow entry: "+err.Error(), http.StatusBadRequest)
		return
	}

	state := s.adultBlockState()
	if *dto.Enabled && !state.RuleSetInstalled {
		http.Error(w, "cannot enable adult-content blocking: missing "+strings.Join(state.Missing, ", ")+
			" — redeploy (scripts/stage.sh ships them) and retry", http.StatusConflict)
		return
	}

	allowChanged := dto.Allow != nil && !slices.Equal(allow, state.Allow)
	if *dto.Enabled == state.Enabled && !allowChanged {
		writeJSON(w, http.StatusOK, state)
		return
	}

	if err := s.deps.Store.Mutate(s.deps.Cfg, func(c *config.Config) error {
		c.DataPlane.Route.AdultBlock = *dto.Enabled
		if dto.Allow != nil {
			c.DataPlane.Route.AdultBlockAllow = config.StringList(allow)
		}
		return nil
	}); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// WithoutCancel: the change is already persisted, so a client disconnect
	// must not leave mihomo routing by the previous value. Same reasoning as
	// PUT /api/ad-block.
	if err := s.rerenderAndReload(context.WithoutCancel(r.Context())); err != nil {
		http.Error(w, "reload: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s.adultBlockState())
}

// normalizeAdultAllow lowercases, trims, accepts the `+.` / `*.` spellings
// operators copy from rule lists, dedupes, and rejects anything that is not a
// bare domain. A nil input (field omitted) returns nil so the caller can tell
// "leave unchanged" from "clear".
func normalizeAdultAllow(in *[]string) ([]string, error) {
	if in == nil {
		return nil, nil
	}
	out := make([]string, 0, len(*in))
	seen := make(map[string]bool, len(*in))
	for _, raw := range *in {
		d := strings.ToLower(strings.TrimSpace(raw))
		d = strings.TrimPrefix(d, "+.")
		d = strings.TrimPrefix(d, "*.")
		d = strings.TrimPrefix(d, ".")
		if d == "" {
			continue
		}
		if err := validateDomainSuffix(d); err != nil {
			return nil, fmt.Errorf("%q: %w", raw, err)
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out, nil
}
