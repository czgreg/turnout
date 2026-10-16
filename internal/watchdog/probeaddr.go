// probeaddr.go — kernel-level manipulation of the liveness address.
//
// The liveness address is the entire signalling channel to the firewall: its
// presence answers the IP-Link probe, its absence does not. Everything here
// is therefore written to be idempotent and to report truthfully, because a
// silent failure means the firewall keeps diverting traffic into a node that
// believes it has already cut over.
//
// Why shell out rather than use netlink:
//
//   - The address may live on lo or on a physical NIC depending on the
//     firewall's probe mode (icmp vs arp), and toggling it needs no special
//     handling beyond picking the right device name.
//   - iproute2 is already a hard dependency of this deployment (iproute.sh
//     uses it), so this adds no new requirement.
//   - The commands are trivially auditable in the journal, which matters
//     when the whole point is being able to reconstruct why a cutover
//     happened at 03:00.
package watchdog

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// Runner executes a command. Swappable in tests.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// IPAddrManager manages one address on one interface via `ip addr`.
type IPAddrManager struct {
	addr   string
	iface  string
	runner Runner
}

// NewIPAddrManager builds an AddressManager for addr on iface.
//
// addr must include no prefix length — a bare address is what an IP-Link
// destination expects, and the code appends the host prefix itself.
func NewIPAddrManager(addr, iface string) *IPAddrManager {
	if iface == "" {
		iface = "lo"
	}
	return &IPAddrManager{addr: addr, iface: iface, runner: defaultRunner}
}

// WithRunner swaps the command runner (tests).
func (m *IPAddrManager) WithRunner(r Runner) *IPAddrManager {
	m.runner = r
	return m
}

func defaultRunner(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// Up ensures the address is present. Idempotent: `ip addr replace` rewrites
// an existing entry rather than failing the way `ip addr add` does.
//
// The prefix length is /32 (or /128 for v6): this is a host route on a
// loopback-style address, and a wider prefix could make the host advertise
// itself as an on-link neighbour for unrelated addresses on that segment.
func (m *IPAddrManager) Up(ctx context.Context) error {
	cidr := m.addr
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	out, err := m.runner(ctx, "ip", "addr", "replace", cidr, "dev", m.iface)
	if err != nil {
		return fmt.Errorf("ip addr replace %s dev %s: %w: %s", cidr, m.iface, err, strings.TrimSpace(out))
	}
	slog.Info("watchdog: liveness address up", "addr", cidr, "dev", m.iface)
	return nil
}

// Down removes the address. Idempotent: `ip addr del` on an absent address
// fails, which we treat as success — the postcondition "not present" already
// holds, and reporting an error would make the watchdog's status lie.
func (m *IPAddrManager) Down(ctx context.Context) error {
	present, err := m.Present(ctx)
	if err != nil {
		return err
	}
	if !present {
		slog.Debug("watchdog: liveness address already down", "addr", m.addr)
		return nil
	}
	cidr := m.addr
	if !strings.Contains(cidr, "/") {
		cidr += "/32"
	}
	out, err := m.runner(ctx, "ip", "addr", "del", cidr, "dev", m.iface)
	if err != nil {
		return fmt.Errorf("ip addr del %s dev %s: %w: %s", cidr, m.iface, err, strings.TrimSpace(out))
	}
	slog.Warn("watchdog: liveness address withdrawn", "addr", cidr, "dev", m.iface)
	return nil
}

// Present reports whether the address is currently configured.
//
// It matches on the exact address rather than grepping loosely: a substring
// match on "10.255.255.3" would also match "10.255.255.30", and a false
// positive here means the watchdog believes it is signalling health when the
// address is not actually there.
func (m *IPAddrManager) Present(ctx context.Context) (bool, error) {
	// `ip -4 -o addr show dev <iface>` prints one line per address, with the
	// CIDR in field 4. Asking for the specific device avoids scanning every
	// interface (and avoids matching the egress NIC's own addresses).
	family := "inet"
	show := "ip -4 -o addr show dev " + m.iface
	if strings.Contains(m.addr, ":") {
		family = "inet6"
		show = "ip -6 -o addr show dev " + m.iface
	}
	args := strings.Fields(show)
	out, err := m.runner(ctx, args[0], args[1:]...)
	if err != nil {
		// A device that does not exist is a configuration error worth
		// surfacing: reporting "not present" would silently disable the
		// signal path.
		return false, fmt.Errorf("cannot read addresses for %s: %w: %s", m.iface, err, strings.TrimSpace(out))
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		// Format: "2: lo    inet 10.255.255.3/32 scope global lo"
		for i, tok := range f {
			if tok != family || i+1 >= len(f) {
				continue
			}
			got := strings.SplitN(f[i+1], "/", 2)[0]
			if got == m.addr {
				return true, nil
			}
		}
	}
	return false, nil
}
