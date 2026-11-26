package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
	"github.com/turnout-gateway/turnout-gateway/internal/xborder"
)

// XBorderLogView is the response of GET and PUT /api/xborder-log.
type XBorderLogView struct {
	Config XBorderLogSettings `json:"config"`
	Status xborder.Status     `json:"status"`
	// DataPlaneLogLevel is shown because enabling requires info or debug;
	// the console explains a rejection with it instead of a bare 400.
	DataPlaneLogLevel string `json:"data_plane_log_level"`
}

// XBorderLogSettings is the operator-editable part of xborder_log. Defaults
// are filled in even while disabled, so the form shows what enabling would
// use.
type XBorderLogSettings struct {
	Enabled        bool   `json:"enabled"`
	Address        string `json:"address"`
	Framing        string `json:"framing"`
	Facility       string `json:"facility"`
	AppName        string `json:"app_name"`
	PollIntervalMs int64  `json:"poll_interval_ms"`
	QueueSize      int    `json:"queue_size"`
}

// xborderMu serializes PUTs: validation reads the current block and the
// apply step swaps running goroutines, and two interleaved requests must not
// leave yaml and the running sink describing different configs.
var xborderMu sync.Mutex

func (s *Server) xborderView() XBorderLogView {
	x := s.deps.Cfg.XBorderLog.WithDefaults()
	v := XBorderLogView{
		Config: XBorderLogSettings{
			Enabled: x.Enabled, Address: x.Address, Framing: x.Framing,
			Facility: x.Facility, AppName: x.AppName,
			PollIntervalMs: x.PollInterval.Milliseconds(), QueueSize: x.QueueSize,
		},
		DataPlaneLogLevel: s.deps.Cfg.DataPlane.LogLevel,
	}
	if s.deps.XBorder != nil {
		v.Status = s.deps.XBorder.Status()
	}
	return v
}

func (s *Server) handleXBorderLogGet(w http.ResponseWriter, _ *http.Request) {
	if s.deps.XBorder == nil {
		http.Error(w, "cross-border log is not available in this process", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, s.xborderView())
}

// handleXBorderLogPut answers PUT /api/xborder-log. Every field is optional;
// only what is present changes. The change is validated with the same
// function config.Load uses, persisted, then applied in-process — no restart.
func (s *Server) handleXBorderLogPut(w http.ResponseWriter, r *http.Request) {
	if s.deps.XBorder == nil {
		http.Error(w, "cross-border log is not available in this process", http.StatusServiceUnavailable)
		return
	}
	var dto struct {
		Enabled        *bool   `json:"enabled"`
		Address        *string `json:"address"`
		Framing        *string `json:"framing"`
		Facility       *string `json:"facility"`
		AppName        *string `json:"app_name"`
		PollIntervalMs *int64  `json:"poll_interval_ms"`
		QueueSize      *int    `json:"queue_size"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&dto); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}

	xborderMu.Lock()
	defer xborderMu.Unlock()

	cand := s.deps.Cfg.XBorderLog
	if dto.Enabled != nil {
		cand.Enabled = *dto.Enabled
	}
	if dto.Address != nil {
		cand.Address = strings.TrimSpace(*dto.Address)
	}
	if dto.Framing != nil {
		cand.Framing = *dto.Framing
	}
	if dto.Facility != nil {
		cand.Facility = *dto.Facility
	}
	if dto.AppName != nil {
		cand.AppName = strings.TrimSpace(*dto.AppName)
	}
	if dto.PollIntervalMs != nil {
		cand.PollInterval = time.Duration(*dto.PollIntervalMs) * time.Millisecond
	}
	if dto.QueueSize != nil {
		cand.QueueSize = *dto.QueueSize
	}
	if cand.Enabled {
		cand = cand.WithDefaults()
	}
	dp := s.deps.Cfg.DataPlane
	if err := config.ValidateXBorderLog(cand, dp.LogLevel, dp.ClashAPI.ExternalController); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Only the xborder_log block changes; everything else (subscriptions
	// included) is written back exactly as it is held in memory.
	if err := s.deps.Store.Mutate(s.deps.Cfg, func(c *config.Config) error {
		c.XBorderLog = cand
		return nil
	}); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.deps.XBorder.Apply(cand); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":     err.Error(),
			"persisted": true,
			"warning":   "saved to gateway.yaml but not applied; restart turnout-gateway to apply",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.xborderView())
}
