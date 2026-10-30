package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// NodeNetwork is the response shape for GET /api/node/network — the fields an
// operator needs to reason about "which segment does this node serve, and can
// I reach it".
//
// APITokenSet is a boolean on purpose: the console needs to know whether the
// control plane is unauthenticated, and must never receive the token itself.
type NodeNetwork struct {
	ClientSubnet string `json:"client_subnet"`  // node.client_subnet — the diverted office segment
	IngressIface string `json:"ingress_iface"`  // node.ingress_iface
	IngressIP    string `json:"ingress_ip"`     // node.ingress_ip
	APIListen    string `json:"api_listen"`     // api.listen
	APITokenSet  bool   `json:"api_token_set"`  // false → setup state (every /api/* is closed until initialised)
	// APITokenSource is "file" (api.token_file, set by the console) or
	// "yaml" (legacy api.token, travels with gateway.yaml — rotate it).
	APITokenSource string `json:"api_token_source,omitempty"`
	// APITLS describes the certificate the control plane presents, nil when
	// api.tls.enabled=false. The fingerprint is deliberately NOT here: an
	// operator must compare it against an out-of-band copy (ssh, Lark), and
	// a value served by the very connection under suspicion proves nothing.
	APITLS *NodeAPITLS `json:"api_tls,omitempty"`
	// AppliedAt is deliberately absent: it would suggest the node re-reads
	// gateway.yaml on its own, which it does not — see applyNetworkChange.
}

// NodeAPITLS is the public part of the API certificate's state.
type NodeAPITLS struct {
	AutoManaged bool     `json:"auto_managed"` // node mints + renews; false = operator-provided files
	NotAfter    string   `json:"not_after"`    // RFC 3339
	SANs        []string `json:"sans"`
}

func (s *Server) handleNodeNetworkGet(w http.ResponseWriter, _ *http.Request) {
	out := NodeNetwork{
		ClientSubnet: s.deps.Cfg.Node.ClientSubnet,
		IngressIface: s.deps.Cfg.Node.IngressIface,
		IngressIP:    s.deps.Cfg.Node.IngressIP,
		APIListen:    s.deps.Cfg.API.Listen,
		APITokenSet:  s.deps.Auth != nil && !s.deps.Auth.InSetup(),
	}
	if s.deps.Auth != nil {
		out.APITokenSource = s.deps.Auth.Source()
	}
	if m := s.deps.TLS; m != nil {
		leaf := m.Leaf()
		sans := append([]string(nil), leaf.DNSNames...)
		for _, ip := range leaf.IPAddresses {
			sans = append(sans, ip.String())
		}
		out.APITLS = &NodeAPITLS{
			AutoManaged: s.deps.Cfg.API.TLS.AutoManaged(),
			NotAfter:    leaf.NotAfter.UTC().Format(time.RFC3339),
			SANs:        sans,
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleNodeNetworkPut answers PUT /api/node/network {"client_subnet": "..."}.
//
// This is the one API edit that escapes turnout-gateway's process: client_subnet
// is consumed by /etc/turnout/env → iproute.sh (iptables TPROXY/DNS rules) and
// by the nft template, neither of which the Go process owns. So a save is a
// four-step fan-out, and every step can fail independently:
//
//  1. persist to gateway.yaml (Store.Mutate — in-memory cfg and disk together)
//  2. regenerate /etc/turnout/env (`--print-env`, the same generator install.sh uses)
//  3. re-render /etc/turnout/nft.conf (render-rules.sh — same script install.sh uses)
//  4. restart turnout-nft.service (re-applies nft + TPROXY), then re-render
//     and hot-reload mihomo so fb-<ip> groups follow the new subnet
//
// Step 4's restart also fires ExecStop of the oneshot, so the ruleset is torn
// down and rebuilt. That gap is short but real — traffic in flight during it
// is not proxied. It is the only correct ordering: iproute.sh reads
// /etc/turnout/env at up-time, so the new subnet must be on disk first.
func (s *Server) handleNodeNetworkPut(w http.ResponseWriter, r *http.Request) {
	var dto struct {
		ClientSubnet *string `json:"client_subnet"`
	}
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dto.ClientSubnet == nil {
		http.Error(w, "client_subnet field is required", http.StatusBadRequest)
		return
	}
	subnet := strings.TrimSpace(*dto.ClientSubnet)
	if err := validateClientSubnet(subnet, s.deps.Cfg.Node.IngressIP); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	prev := s.deps.Cfg.Node.ClientSubnet
	if subnet == prev {
		// Idempotent: a double-click must not bounce the data plane.
		s.handleNodeNetworkGet(w, r)
		return
	}

	if err := s.deps.Store.Mutate(s.deps.Cfg, func(c *config.Config) error {
		c.Node.ClientSubnet = subnet
		return nil
	}); err != nil {
		http.Error(w, "persist: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// From here on the config on disk and in memory are the new value; a
	// failure leaves the node running the OLD rules. Say so explicitly
	// rather than returning a bare 500 the operator will read as "nothing
	// happened".
	if err := s.applyNetworkChange(r.Context()); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error":         err.Error(),
			"persisted":     subnet,
			"previous":      prev,
			"warning":       "gateway.yaml holds the new client_subnet but the node may still be running the previous rules — fix the reported step, then re-save or re-run install.sh",
			"client_subnet": subnet,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"client_subnet": subnet,
		"previous":      prev,
		"applied":       true,
	})
}

// applyNetworkChange pushes the persisted config out to every consumer that
// does not re-read gateway.yaml on its own.
func (s *Server) applyNetworkChange(ctx context.Context) error {
	// 1. /etc/turnout/env — sourced by iproute.sh and render-rules.sh.
	if err := s.writeRuntimeEnv(); err != nil {
		return fmt.Errorf("write /etc/turnout/env: %w", err)
	}
	// 2. nft.conf — template + env.
	if out, err := exec.Command("/etc/turnout/render-rules.sh").CombinedOutput(); err != nil {
		return fmt.Errorf("render-rules.sh: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// 3. iptables + nft live rules.
	if out, err := exec.Command("systemctl", "restart", "turnout-nft.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart turnout-nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// 4. Data plane. The renderer holds a copy of NodeConfig, so re-seat it
	// before re-rendering or fb-<ip> groups keep the old subnet. WithoutCancel:
	// the steps above already happened, so a client disconnect must not abort
	// the reload and leave mihomo on the previous config.
	rctx := context.WithoutCancel(ctx)
	s.deps.Renderer.SetNode(s.deps.Cfg.Node)
	if err := s.rerenderAndReload(rctx); err != nil {
		return fmt.Errorf("reload data plane: %w", err)
	}
	return nil
}

// writeRuntimeEnv regenerates /etc/turnout/env from the current config using
// the binary's own --print-env, then swaps it in atomically. Re-parsing YAML
// in Go here would duplicate that generator; install.sh already relies on it
// being the single source.
func (s *Server) writeRuntimeEnv() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	out, err := exec.Command(exe, "--config", s.deps.Store.Path(), "--print-env").Output()
	if err != nil {
		return fmt.Errorf("%s --print-env: %w", exe, err)
	}
	if len(out) == 0 {
		return fmt.Errorf("%s --print-env produced no output", exe)
	}
	tmp := "/etc/turnout/env.tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, "/etc/turnout/env"); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// validateClientSubnet mirrors what iproute.sh and the renderer can actually
// consume: a CIDR, IPv4, normalised (host bits clear).
//
// ingressIP is node.ingress_ip — the address diverted traffic lands on. If the
// segment cannot contain it the operator has almost certainly swapped the two
// fields; catching it here beats debugging an empty data path.
func validateClientSubnet(s, ingressIP string) error {
	if s == "" {
		return fmt.Errorf("client_subnet must not be empty")
	}
	if strings.ContainsAny(s, " \t\n\r") {
		return fmt.Errorf("client_subnet must not contain whitespace")
	}
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("client_subnet %q is not a CIDR: %w", s, err)
	}
	if ip.To4() == nil {
		return fmt.Errorf("client_subnet %q must be IPv4 (TPROXY rules are IPv4-only)", s)
	}
	ones, bits := ipnet.Mask.Size()
	if ones > bits-1 {
		return fmt.Errorf("client_subnet %q is a single host — the diverted segment must cover more than one address", s)
	}
	if ones < 8 {
		return fmt.Errorf("client_subnet %q is wider than /8 — that would divert effectively the whole internet", s)
	}
	// Host bits set (e.g. 192.168.0.5/16) would make iptables match the
	// network anyway, but the API would report a subnet that is not what
	// the rules use. Reject rather than silently normalise.
	if !ip.Equal(ipnet.IP) {
		return fmt.Errorf("client_subnet %q has host bits set; use the network address %s", s, ipnet.IP)
	}
	if tip := net.ParseIP(ingressIP); tip != nil && !ipnet.Contains(tip) {
		return fmt.Errorf("client_subnet %q does not contain ingress_ip %s — diverted traffic would never arrive", s, ingressIP)
	}
	return nil
}
