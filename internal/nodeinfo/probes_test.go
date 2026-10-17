package nodeinfo

// Tests for the parsing half of the ingress probes.
//
// These functions decide what the console shows under "引流口 / 引流地址 /
// 回程路由", and both failure directions are silent:
//   - a substring match on the address reports the ingress link healthy while
//     the firewall has no next-hop to send to;
//   - returning the wrong default route line makes the operator believe
//     unproxied traffic is being handed back when it is not.

import "testing"

func TestParseAddrPresent_ExactMatchOnly(t *testing.T) {
	// Realistic `ip -4 -o addr show` output, multiple interfaces.
	const out = `1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: ens18    inet 10.1.2.5/24 brd 10.1.2.255 scope global ens18\       valid_lft forever preferred_lft forever
3: ens19    inet 10.255.255.2/30 scope global ens19\       valid_lft forever preferred_lft forever`

	cases := []struct {
		name string
		addr string
		want bool
	}{
		{"present exactly", "10.255.255.2", true},
		{"present, different interface", "10.1.2.5", true},
		{"absent", "10.255.255.3", false},
		// The substring trap: every one of these is a prefix of an address
		// that IS present, and a naive strings.Contains would say true.
		{"prefix of a present address", "10.255.255.", false},
		{"shorter prefix", "10.1.2", false},
		{"longer than any present", "10.255.255.20", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseAddrPresent(out, tc.addr); got != tc.want {
				t.Errorf("parseAddrPresent(%q) = %v, want %v", tc.addr, got, tc.want)
			}
		})
	}
}

// A liveness address like 10.255.255.3 must not match 10.255.255.30 — the
// exact shape the exact-match rule exists for.
func TestParseAddrPresent_SharedPrefix(t *testing.T) {
	const out = `2: lo    inet 10.255.255.30/32 scope global lo`
	if parseAddrPresent(out, "10.255.255.3") {
		t.Error("10.255.255.3 must not match 10.255.255.30")
	}
	if !parseAddrPresent(out, "10.255.255.30") {
		t.Error("10.255.255.30 should match itself")
	}
}

func TestParseAddrPresent_EmptyOutput(t *testing.T) {
	if parseAddrPresent("", "10.255.255.3") {
		t.Error("empty output cannot contain the address")
	}
}

// IPv6 lines use "inet6", which the v4 query never emits — they must not be
// mistaken for a match.
func TestParseAddrPresent_IgnoresInet6(t *testing.T) {
	const out = `2: lo    inet6 fd00::3/128 scope global`
	if parseAddrPresent(out, "fd00::3") {
		t.Error("inet6 lines must not satisfy the IPv4 check")
	}
}

func TestParseDefaultRoute(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "single default",
			out:  "default via 10.255.255.1 dev ens19 proto static metric 100\n",
			want: "default via 10.255.255.1 dev ens19 proto static metric 100",
		},
		{
			// With multiple defaults the kernel prefers the lowest metric;
			// only the first line is surfaced.
			name: "multiple defaults reports the first",
			out:  "default via 10.255.255.1 dev ens19 metric 100\ndefault via 10.1.2.254 dev ens18 metric 200\n",
			want: "default via 10.255.255.1 dev ens19 metric 100",
		},
		{
			name: "none",
			out:  "",
			want: "",
		},
		{
			name: "whitespace only",
			out:  "  \n\t\n",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDefaultRoute(tc.out); got != tc.want {
				t.Errorf("parseDefaultRoute(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}
