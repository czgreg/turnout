package xborder

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testSender(t *testing.T, addr, framing string, q int) *SyslogSender {
	t.Helper()
	s, err := NewSyslogSender(SyslogConfig{
		Address: addr, Framing: framing, Facility: "local5",
		AppName: "turnout-xborder", Hostname: "gw test", QueueSize: q,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 11, 24, 10, 0, 0, 123456000, time.FixedZone("CST", 8*3600)) }
	return s
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln
}

func accept(t *testing.T, ln net.Listener) net.Conn {
	t.Helper()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	return c
}

func TestSyslogFrameLF(t *testing.T) {
	ln := listen(t)
	s := testSender(t, ln.Addr().String(), "lf", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Enqueue(Record{Schema: Schema, Event: EventClose, Seq: 7, Src: SrcFields{IP: "192.0.2.10", Port: 1}})
	s.Enqueue(Record{Schema: Schema, Event: EventDialError, Seq: 8})
	c := accept(t, ln)
	defer c.Close()
	br := bufio.NewReader(c)

	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	// local5 = facility 21; info = 6 → 174.
	prefix := "<174>1 2026-11-24T10:00:00.123456+08:00 gw-test turnout-xborder "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("frame = %q, want prefix %q", line, prefix)
	}
	f := strings.SplitN(strings.TrimSuffix(line, "\n"), " ", 8)
	if f[5] != "close" || f[6] != "-" {
		t.Errorf("MSGID/SD = %q %q", f[5], f[6])
	}
	var r Record
	if err := json.Unmarshal([]byte(f[7]), &r); err != nil || r.Seq != 7 || r.Src.IP != "192.0.2.10" {
		t.Errorf("body %q: %v %+v", f[7], err, r)
	}
	line, _ = br.ReadString('\n')
	if !strings.HasPrefix(line, "<172>1 ") || !strings.Contains(line, " dial_error - ") {
		t.Errorf("dial_error must be warning (172) with MSGID dial_error: %q", line)
	}
}

func TestSyslogFrameOctetCounting(t *testing.T) {
	ln := listen(t)
	s := testSender(t, ln.Addr().String(), "octet-counting", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Enqueue(Record{Schema: Schema, Event: EventClose, Dst: DstFields{Host: "例子.example"}})
	c := accept(t, ln)
	defer c.Close()
	br := bufio.NewReader(c)
	lenStr, err := br.ReadString(' ')
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(lenStr))
	if err != nil {
		t.Fatalf("length prefix %q", lenStr)
	}
	msg := make([]byte, n)
	if _, err := io_ReadFull(br, msg); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(msg), "<174>1 ") || !strings.HasSuffix(string(msg), "}") {
		t.Errorf("octet count must be in bytes (UTF-8 host): %q", msg)
	}
}

func io_ReadFull(r *bufio.Reader, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		m, err := r.Read(b[n:])
		n += m
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func TestSyslogQueueDropsOldest(t *testing.T) {
	s := testSender(t, "127.0.0.1:1", "lf", 3)
	for i := 1; i <= 5; i++ {
		s.Enqueue(Record{Event: EventClose, Seq: uint64(i)})
	}
	if got := s.dropped.Load(); got != 2 {
		t.Errorf("dropped = %d, want 2", got)
	}
	var seqs []uint64
	for len(s.q) > 0 {
		f := string(<-s.q)
		var r Record
		json.Unmarshal([]byte(f[strings.Index(f, "{"):]), &r)
		seqs = append(seqs, r.Seq)
	}
	if len(seqs) != 3 || seqs[0] != 3 || seqs[2] != 5 {
		t.Errorf("kept %v, want newest [3 4 5]", seqs)
	}
}

// A server restart closes our connection. The next record must go out on a
// fresh connection instead of vanishing into the dead socket.
func TestSyslogReconnectsAfterServerClose(t *testing.T) {
	ln := listen(t)
	s := testSender(t, ln.Addr().String(), "lf", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	s.Enqueue(Record{Event: EventClose, Seq: 1})
	c1 := accept(t, ln)
	if _, err := bufio.NewReader(c1).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	c1.Close()
	time.Sleep(50 * time.Millisecond) // let the FIN arrive

	s.Enqueue(Record{Event: EventClose, Seq: 2})
	c2 := accept(t, ln)
	defer c2.Close()
	line, err := bufio.NewReader(c2).ReadString('\n')
	if err != nil || !strings.Contains(line, `"seq":2`) {
		t.Fatalf("second record on new connection: %q %v", line, err)
	}
}

func TestSyslogQueuesWhileServerDown(t *testing.T) {
	ln := listen(t)
	addr := ln.Addr().String()
	ln.Close() // nothing listening yet
	s := testSender(t, addr, "lf", 10)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	s.Enqueue(Record{Event: EventClose, Seq: 1})
	time.Sleep(200 * time.Millisecond)

	ln2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("port reuse not available: %v", err)
	}
	defer ln2.Close()
	c := accept(t, ln2)
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.Contains(line, `"seq":1`) {
		t.Fatalf("queued record not delivered after server came up: %q %v", line, err)
	}
}

func TestSyslogBadFacility(t *testing.T) {
	if _, err := NewSyslogSender(SyslogConfig{Facility: "user"}); err == nil {
		t.Error("facility user must be rejected")
	}
}
