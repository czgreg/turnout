package api

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// NodeSignal is the response shape for GET /api/node/signal — the watchdog's
// operator-facing knobs.
//
// Why this is separate from PUT /api/node/network: liveness_ip is consumed
// only by the watchdog goroutine, which is constructed once at process start.
// It touches neither /etc/turnout/env nor nft.conf, so applying a change is
// "persist + restart", not the four-step fan-out network.go performs.
//
// The one thing this endpoint must get right is the old address: the watchdog
// only adds and removes LivenessIP, so changing the value without removing
// the previous one leaves both /32s answering the firewall's probe.
type NodeSignal struct {
	LivenessIP          string `json:"liveness_ip"`
	LivenessIface       string `json:"liveness_iface"`
	AutoFailover        bool   `json:"auto_failover"`
	NotifyOnStateChange bool   `json:"notify_on_state_change"`
	// IngressIP / ReturnGateway are the two addresses liveness_ip must never
	// collide with; surfaced so the UI can explain a rejection.
	IngressIP     string `json:"ingress_ip"`
	ReturnGateway string `json:"return_gateway"`
}

func (s *Server) handleNodeSignalGet(w http.ResponseWriter, _ *http.Request) {
	wd := s.deps.Cfg.Watchdog
	writeJSON(w, http.StatusOK, NodeSignal{
		LivenessIP:          wd.LivenessIP,
		LivenessIface:       wd.LivenessIface,
		AutoFailover:        wd.AutoFailover,
		NotifyOnStateChange: wd.ShouldNotify(),
		IngressIP:           s.deps.Cfg.Node.IngressIP,
		ReturnGateway:       s.deps.Cfg.Node.Return.GatewayIP,
	})
}

// handleNodeSignalPut answers PUT /api/node/signal.
//
// Every field is optional; only what is present is changed. The apply step is
// a restart of this very process, so the response describes what WILL happen
// rather than what already did — the address removal happens synchronously
// (it is what makes the change safe), the restart is scheduled a couple of
// seconds out so this response reaches the client first.
func (s *Server) handleNodeSignalPut(w http.ResponseWriter, r *http.Request) {
	var dto struct {
		LivenessIP          *string `json:"liveness_ip"`
		LivenessIface       *string `json:"liveness_iface"`
		AutoFailover        *bool   `json:"auto_failover"`
		NotifyOnStateChange *bool   `json:"notify_on_state_change"`
	}
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dto.LivenessIP == nil && dto.LivenessIface == nil &&
		dto.AutoFailover == nil && dto.NotifyOnStateChange == nil {
		http.Error(w, "no fields to update", http.StatusBadRequest)
		return
	}

	prev := s.deps.Cfg.Watchdog
	if dto.LivenessIP != nil {
		if err := validateLivenessIP(*dto.LivenessIP, s.deps.Cfg.Node.IngressIP, s.deps.Cfg.Node.Return.GatewayIP); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if dto.LivenessIface != nil && strings.TrimSpace(*dto.LivenessIface) == "" {
		http.Error(w, "liveness_iface must not be empty (use \"lo\" or the ingress NIC)", http.StatusBadRequest)
		return
	}

	if err := s.deps.Store.Mutate(s.deps.Cfg, func(c *config.Config) error {
		if dto.LivenessIP != nil {
			c.Watchdog.LivenessIP = strings.TrimSpace(*dto.LivenessIP)
		}
		if dto.LivenessIface != nil {
			c.Watchdog.LivenessIface = strings.TrimSpace(*dto.LivenessIface)
		}
		if dto.AutoFailover != nil {
			c.Watchdog.AutoFailover = *dto.AutoFailover
		}
		if dto.NotifyOnStateChange != nil {
			v := *dto.NotifyOnStateChange
			c.Watchdog.NotifyOnStateChange = &v
		}
		return nil
	}); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove the previous address BEFORE restarting. The watchdog only acts on
	// transitions, so a stale /32 would linger forever and keep answering the
	// firewall's probe — the exact silent failure this whole subsystem exists
	// to prevent. Best-effort: a failure here is reported, not fatal, because
	// the config is already persisted.
	ifaceChanged := dto.LivenessIface != nil && strings.TrimSpace(*dto.LivenessIface) != prev.LivenessIface
	ipChanged := dto.LivenessIP != nil && strings.TrimSpace(*dto.LivenessIP) != prev.LivenessIP
	removed := ""
	if (ipChanged || ifaceChanged) && prev.LivenessIP != "" {
		if err := removeLivenessAddr(prev.LivenessIP, prev.LivenessIface); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{
				"error":     err.Error(),
				"persisted": true,
				"warning":   fmt.Sprintf("gateway.yaml holds the new settings but the previous liveness address %s may still be up — remove it manually with: ip addr del %s/32 dev %s", prev.LivenessIP, prev.LivenessIP, prev.LivenessIface),
			})
			return
		}
		removed = prev.LivenessIP
	}

	// The watchdog is built once in cmd/gateway/main.go, so nothing here takes
	// effect until this process restarts. systemd-run schedules that restart in
	// a transient unit OUTSIDE our cgroup — a plain child process would be
	// killed with us mid-restart.
	out, err := restartSelf()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":       err.Error(),
			"persisted":   true,
			"removed_old": removed,
			"warning":     "settings saved but the restart did not start; run 'systemctl restart turnout-gateway' to apply",
		})
		return
	}

	resp := map[string]any{
		"restart":     "scheduled",
		"removed_old": removed,
		"note":        "turnout-gateway restarts in ~2s; the liveness address reappears after recover_threshold clean rounds",
	}
	if out != "" {
		resp["detail"] = out
	}
	writeJSON(w, http.StatusOK, resp)
}

// validateLivenessIP enforces the three failure modes install.sh guards
// against, because a UI is a much easier place to get this wrong than a
// reviewed yaml.
func validateLivenessIP(s, ingressIP, returnGW string) error {
	if s == "" {
		return fmt.Errorf("liveness_ip must not be empty — without it the node cannot signal its health to the firewall")
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("liveness_ip %q is not a valid IPv4 address", s)
	}
	if ingressIP != "" && ip.Equal(net.ParseIP(ingressIP)) {
		return fmt.Errorf("liveness_ip must not equal ingress_ip (%s) — withdrawing it would also drop SSH and the API", ingressIP)
	}
	if returnGW != "" && ip.Equal(net.ParseIP(returnGW)) {
		return fmt.Errorf("liveness_ip must not equal return.gateway_ip (%s) — that is the firewall's own address", returnGW)
	}
	return nil
}

func removeLivenessAddr(addr, iface string) error {
	if iface == "" {
		iface = "lo"
	}
	out, err := exec.Command("ip", "addr", "del", addr+"/32", "dev", iface).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip addr del %s/32 dev %s: %w: %s", addr, iface, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// restartSelf schedules `systemctl restart turnout-gateway` a couple of seconds
// out via a transient systemd unit. The delay is what lets this HTTP response
// flush before the process goes away, and systemd-run puts the job outside our
// cgroup — a plain background child would be killed with us mid-restart.
func restartSelf() (string, error) {
	out, err := exec.Command("systemd-run", "--on-active=2", "--collect", "--quiet",
		"--unit=turnout-gateway-selfrestart",
		"systemctl", "restart", "turnout-gateway").CombinedOutput()
	return strings.TrimSpace(string(out)), err
}
