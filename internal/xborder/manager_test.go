package xborder

import (
	"bufio"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// Records queued while the old server was unreachable must reach the new
// server after the address is changed, not be dropped with the old sender.
func TestManagerCarriesBacklogToNewAddress(t *testing.T) {
	dead := listen(t)
	deadAddr := dead.Addr().String()
	dead.Close()
	live := listen(t)

	m := NewManager(Options{APIAddr: "127.0.0.1:1", Hostname: "gw"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	on := config.XBorderLogConfig{Enabled: true, Address: deadAddr}
	if err := m.Start(ctx, on); err != nil {
		t.Fatal(err)
	}
	m.emit(Record{Schema: Schema, Event: EventClose, Seq: 41})
	m.emit(Record{Schema: Schema, Event: EventClose, Seq: 42})
	if st := m.Status(); !st.Running || st.Connected {
		t.Fatalf("status before swap = %+v", st)
	}

	on.Address = live.Addr().String()
	if err := m.Apply(on); err != nil {
		t.Fatal(err)
	}
	c := accept(t, live)
	defer c.Close()
	br := bufio.NewReader(c)
	for _, want := range []string{`"seq":41`, `"seq":42`} {
		line, err := br.ReadString('\n')
		if err != nil || !strings.Contains(line, want) {
			t.Fatalf("want %s on new server, got %q %v", want, line, err)
		}
	}

	if err := m.Apply(config.XBorderLogConfig{}); err != nil {
		t.Fatal(err)
	}
	if st := m.Status(); st.Running {
		t.Errorf("disabled manager still running: %+v", st)
	}
	m.emit(Record{Seq: 99}) // must be a no-op, not a panic
}

// A poll-interval change restarts the collector; an address change alone
// must not (a restart forgets short connections waiting for a sample).
func TestManagerRestartsCollectorOnlyWhenNeeded(t *testing.T) {
	a := listen(t)
	m := NewManager(Options{APIAddr: "127.0.0.1:1", Hostname: "gw"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := config.XBorderLogConfig{Enabled: true, Address: a.Addr().String()}
	if err := m.Start(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	c1 := m.coll
	cfg.Framing = "octet-counting"
	m.Apply(cfg)
	if m.coll != c1 {
		t.Error("framing change restarted the collector")
	}
	cfg.PollInterval = 2 * time.Second
	m.Apply(cfg)
	if m.coll == c1 {
		t.Error("poll interval change did not restart the collector")
	}
	m.Apply(config.XBorderLogConfig{})
}

func TestManagerStartDisabledRunsNothing(t *testing.T) {
	m := NewManager(Options{APIAddr: "127.0.0.1:1"})
	if err := m.Start(context.Background(), config.XBorderLogConfig{Address: "192.0.2.1:514"}); err != nil {
		t.Fatal(err)
	}
	if m.coll != nil || m.sender != nil || m.Status().Running {
		t.Error("disabled config started goroutines")
	}
}
