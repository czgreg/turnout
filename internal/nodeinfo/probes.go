package nodeinfo

import (
	"bufio"
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// unameR returns "uname -r" — kernel release. Linux-only; on other OSes
// returns runtime.GOOS for diagnostic purposes.
func unameR() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// osPretty pulls PRETTY_NAME from /etc/os-release. Empty if file missing.
func osPretty() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			v := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// readUptime parses /proc/uptime — first field is seconds since boot.
func readUptime() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(f)
}

// listInterfaces returns named interfaces with their primary IPv4 address.
// Skips loopback and interfaces with no IPv4. Order matches OS enumeration.
func listInterfaces() []Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(ifaces))
	for _, ifa := range ifaces {
		if ifa.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifa.Addrs()
		if err != nil {
			continue
		}
		var v4 string
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil {
				v4 = ipnet.IP.String()
				break
			}
		}
		if v4 == "" {
			continue
		}
		out = append(out, Interface{Name: ifa.Name, IPv4: v4})
	}
	return out
}

// linkUp reports whether the named interface exists and is operationally up.
//
// Reads /sys/class/net/<iface>/operstate rather than shelling out to `ip
// link show`: it is one file read instead of a fork, and this runs on the
// 5s reporting tick.
//
// operstate values: "up" is the one we want. "unknown" is reported by some
// virtual devices that are in fact usable (it means the driver does not
// expose carrier state), so it is treated as up — reporting a working
// interface as down is worse than the reverse here, because this field is
// read by an operator deciding whether to walk to the datacentre.
func linkUp(ctx context.Context, iface string) bool {
	if iface == "" {
		return false
	}
	b, err := os.ReadFile("/sys/class/net/" + iface + "/operstate")
	if err != nil {
		return false
	}
	switch strings.TrimSpace(string(b)) {
	case "up", "unknown":
		return true
	default:
		return false
	}
}

// addrPresent reports whether addr is configured on iface.
//
// Matches on the exact address, not a substring: "10.255.255.3" appears
// inside "10.255.255.30", and a false positive here would report the ingress
// link as healthy while the firewall has no next-hop to send to.
func addrPresent(ctx context.Context, iface, addr string) bool {
	if addr == "" {
		return false
	}
	// If iface is unknown, scan all of them rather than guessing — an empty
	// iface is a config problem, and reporting "address missing" would
	// obscure it.
	args := []string{"-4", "-o", "addr", "show"}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "ip", args...).Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		for i, tok := range f {
			if tok != "inet" || i+1 >= len(f) {
				continue
			}
			if strings.SplitN(f[i+1], "/", 2)[0] == addr {
				return true
			}
		}
	}
	return false
}

// defaultRoute returns the current IPv4 default route as a one-line string,
// or "" when there is none.
//
// The bypass role depends on this pointing at the firewall: it is how
// unproxied traffic gets handed back. A missing or wrong default route is
// therefore a first-class failure, not a detail — which is why it is
// surfaced verbatim rather than reduced to a boolean.
func defaultRoute(ctx context.Context) string {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return ""
	}
	return strings.TrimSpace(lines[0])
}

// systemdState: `systemctl is-active <unit>` — returns the textual state
// ("active", "inactive", "failed", "activating", ...). Empty string on error.
func systemdState(ctx context.Context, unit string) string {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(c, "systemctl", "is-active", unit).Output()
	return strings.TrimSpace(string(out))
}

// mihomoVersion: `mihomo -v` — first line, parsed.
// Typical output: "Mihomo Meta v1.19.26 linux amd64 with go1.26.3 ...".
// Returns just "v1.19.26" or empty on error.
func mihomoVersion(ctx context.Context) string {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "/usr/local/bin/mihomo", "-v").Output()
	if err != nil {
		return ""
	}
	first, _, _ := strings.Cut(string(out), "\n")
	for _, tok := range strings.Fields(first) {
		if strings.HasPrefix(tok, "v") {
			return tok
		}
	}
	return strings.TrimSpace(first)
}
