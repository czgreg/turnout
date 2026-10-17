package watchdog

// Tests for the liveness-address manager.
//
// The exact-match behaviour is the point of this file: `Present` gates every
// state transition, so a substring match on "10.255.255.3" would report the
// address as held whenever "10.255.255.30" (a different host's address) is
// configured. The watchdog would then believe it is signalling health while
// the firewall's probe goes nowhere.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRunner records calls and returns canned output.
type fakeRunner struct {
	out   string
	err   error
	calls [][]string
}

func (f *fakeRunner) run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

func (f *fakeRunner) calledWith(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), substr) {
			return true
		}
	}
	return false
}

func newAddrMgr(addr, iface string, fr *fakeRunner) *IPAddrManager {
	return NewIPAddrManager(addr, iface).WithRunner(fr.run)
}

func TestPresent_ExactMatchOnly(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "exact /32 present",
			out:  "2: lo    inet 10.255.255.3/32 scope global lo\\       valid_lft forever",
			want: true,
		},
		{
			// The bug this guards: .30 contains .3 as a prefix.
			name: "different address sharing a prefix",
			out:  "2: lo    inet 10.255.255.30/32 scope global lo\\       valid_lft forever",
			want: false,
		},
		{
			name: "empty output (no addresses)",
			out:  "",
			want: false,
		},
		{
			name: "only other interfaces' addresses",
			out:  "3: ens18    inet 10.1.2.1/24 brd 10.1.2.255 scope global ens18",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := &fakeRunner{out: tc.out}
			got, err := newAddrMgr("10.255.255.3", "lo", fr).Present(context.Background())
			if err != nil {
				t.Fatalf("Present: %v", err)
			}
			if got != tc.want {
				t.Errorf("Present = %v, want %v (output %q)", got, tc.want, tc.out)
			}
		})
	}
}

// An unreadable interface is a configuration error, not "absent": reporting
// absent would silently disable the signal path.
func TestPresent_DeviceErrorPropagates(t *testing.T) {
	fr := &fakeRunner{err: errors.New("does not exist")}
	_, err := newAddrMgr("10.255.255.3", "nosuch0", fr).Present(context.Background())
	if err == nil {
		t.Fatal("expected an error for a nonexistent device")
	}
	if !strings.Contains(err.Error(), "nosuch0") {
		t.Errorf("error should name the device, got %v", err)
	}
}

func TestPresent_UsesIPv6QueryForV6Address(t *testing.T) {
	fr := &fakeRunner{out: "2: lo    inet6 fd00::3/128 scope global"}
	got, err := newAddrMgr("fd00::3", "lo", fr).Present(context.Background())
	if err != nil {
		t.Fatalf("Present: %v", err)
	}
	if !got {
		t.Error("v6 address should be found")
	}
	if !fr.calledWith("ip -6") {
		t.Errorf("expected an -6 query, calls: %v", fr.calls)
	}
}

func TestUp_UsesReplaceWithHostPrefix(t *testing.T) {
	fr := &fakeRunner{}
	if err := newAddrMgr("10.255.255.3", "lo", fr).Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	// `replace`, not `add`: add fails when the address exists, and the
	// watchdog calls Up on every recovery.
	if !fr.calledWith("ip addr replace 10.255.255.3/32 dev lo") {
		t.Errorf("unexpected call: %v", fr.calls)
	}
}

// Down on an absent address must succeed: the postcondition already holds,
// and returning an error would make the status report a failure that did not
// happen.
func TestDown_AbsentIsSuccess(t *testing.T) {
	fr := &fakeRunner{out: ""} // Present → false
	if err := newAddrMgr("10.255.255.3", "lo", fr).Down(context.Background()); err != nil {
		t.Fatalf("Down on absent address must be a no-op success, got %v", err)
	}
	if fr.calledWith("ip addr del") {
		t.Errorf("must not issue a delete when the address is absent: %v", fr.calls)
	}
}

func TestDown_PresentIssuesDelete(t *testing.T) {
	fr := &fakeRunner{out: "2: lo    inet 10.255.255.3/32 scope global lo"}
	if err := newAddrMgr("10.255.255.3", "lo", fr).Down(context.Background()); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if !fr.calledWith("ip addr del 10.255.255.3/32 dev lo") {
		t.Errorf("expected a delete, calls: %v", fr.calls)
	}
}

// The interface matters: binding to lo while the firewall probes with ARP
// (which does not cross layer 3) is a deployment error, and the manager must
// at least direct its commands at the configured device.
func TestManager_UsesConfiguredInterface(t *testing.T) {
	fr := &fakeRunner{}
	m := newAddrMgr("10.255.255.3", "ens19", fr)
	if err := m.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if !fr.calledWith("dev ens19") {
		t.Errorf("expected dev ens19, calls: %v", fr.calls)
	}
}

func TestNewIPAddrManager_DefaultsToLoopback(t *testing.T) {
	fr := &fakeRunner{}
	m := newAddrMgr("10.255.255.3", "", fr)
	if err := m.Up(context.Background()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	if !fr.calledWith("dev lo") {
		t.Errorf("empty iface should default to lo, calls: %v", fr.calls)
	}
}
