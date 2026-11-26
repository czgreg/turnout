package xborder

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// SyslogConfig is the sender's view of config.XBorderLogConfig.
type SyslogConfig struct {
	Address   string
	Framing   string // "lf" | "octet-counting"
	Facility  string // local0..local7
	AppName   string
	Hostname  string
	QueueSize int
}

// SyslogSender writes RFC 5424 messages, one JSON record each, to a TCP
// syslog server. Enqueue never blocks: when the queue is full the oldest
// record is dropped and counted, so a dead server costs records, not
// forwarding.
//
// Plain TCP has no acknowledgement. A record written into the socket just
// before the server dies can be lost without an error; the receiver sees
// it as a gap in seq.
type SyslogSender struct {
	cfg      SyslogConfig
	facility int
	host     string
	pid      int
	q        chan []byte

	sent    atomic.Uint64
	dropped atomic.Uint64

	dial func(ctx context.Context, addr string) (net.Conn, error)
	now  func() time.Time
}

func NewSyslogSender(cfg SyslogConfig) (*SyslogSender, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(cfg.Facility, "local"))
	if !strings.HasPrefix(cfg.Facility, "local") || err != nil || n < 0 || n > 7 {
		return nil, fmt.Errorf("xborder: facility %q: want local0..local7", cfg.Facility)
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 10000
	}
	d := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	return &SyslogSender{
		cfg:      cfg,
		facility: 16 + n,
		host:     syslogHostname(cfg.Hostname),
		pid:      os.Getpid(),
		q:        make(chan []byte, cfg.QueueSize),
		dial: func(ctx context.Context, addr string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", addr)
		},
		now: time.Now,
	}, nil
}

// syslogHostname makes a value legal for the RFC 5424 HOSTNAME field
// (printable US-ASCII, no spaces, 1..255).
func syslogHostname(h string) string {
	b := []byte(h)
	for i, c := range b {
		if c < 33 || c > 126 {
			b[i] = '-'
		}
	}
	if len(b) == 0 {
		return "-"
	}
	if len(b) > 255 {
		b = b[:255]
	}
	return string(b)
}

const (
	sevWarning = 4
	sevInfo    = 6
)

// Enqueue formats r and queues it. Safe for concurrent use.
func (s *SyslogSender) Enqueue(r Record) {
	body, err := json.Marshal(r)
	if err != nil {
		slog.Error("xborder: marshal record", "err", err)
		return
	}
	sev := sevInfo
	if r.Event == EventDialError {
		sev = sevWarning
	}
	msg := fmt.Sprintf("<%d>1 %s %s %s %d %s - %s",
		s.facility*8+sev, s.now().Format("2006-01-02T15:04:05.000000Z07:00"),
		s.host, s.cfg.AppName, s.pid, r.Event, body)
	var frame []byte
	if s.cfg.Framing == "octet-counting" {
		frame = []byte(strconv.Itoa(len(msg)) + " " + msg)
	} else {
		frame = []byte(msg + "\n")
	}
	for {
		select {
		case s.q <- frame:
			return
		default:
		}
		// Full: drop the oldest so the newest survives a long outage.
		select {
		case <-s.q:
			s.dropped.Add(1)
		default:
		}
	}
}

// Run sends until ctx is cancelled, then makes one short attempt to flush
// what is still queued.
func (s *SyslogSender) Run(ctx context.Context) {
	var conn net.Conn
	var cur []byte
	backoff := time.Second
	failing := false
	report := time.NewTicker(time.Minute)
	defer report.Stop()
	var lastDropped uint64

	defer func() {
		if conn != nil {
			s.flush(conn, cur)
			conn.Close()
		}
	}()

	for {
		if cur == nil {
			select {
			case <-ctx.Done():
				return
			case cur = <-s.q:
			case <-report.C:
				if d := s.dropped.Load(); d != lastDropped {
					slog.Warn("xborder: records dropped, send queue was full",
						"dropped_total", d, "dropped_last_minute", d-lastDropped,
						"sent_total", s.sent.Load(), "queued", len(s.q))
					lastDropped = d
				}
				continue
			}
		}
		if conn != nil && peerClosed(conn) {
			conn.Close()
			conn = nil
		}
		if conn == nil {
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			c, err := s.dial(dctx, s.cfg.Address)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !failing {
					slog.Warn("xborder: syslog server unreachable, queueing records",
						"addr", s.cfg.Address, "err", err)
					failing = true
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				if backoff < 30*time.Second {
					backoff *= 2
				}
				continue
			}
			conn = c
			backoff = time.Second
			if failing {
				slog.Info("xborder: syslog server reachable again", "addr", s.cfg.Address, "queued", len(s.q))
				failing = false
			} else {
				slog.Info("xborder: connected to syslog server", "addr", s.cfg.Address)
			}
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(cur); err != nil {
			slog.Warn("xborder: syslog write failed, reconnecting", "addr", s.cfg.Address, "err", err)
			conn.Close()
			conn = nil
			continue // retry cur on a fresh connection
		}
		s.sent.Add(1)
		cur = nil
	}
}

// peerClosed reports whether the server has closed the connection. A
// syslog server never sends data, so a readable EOF means it is gone;
// writing first would succeed into the kernel buffer and lose the record.
func peerClosed(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	var b [1]byte
	_, err := c.Read(b[:])
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true // io.EOF or a reset: either way the connection is dead
}

// flush writes cur and whatever is queued, giving up after 2s.
func (s *SyslogSender) flush(conn net.Conn, cur []byte) {
	deadline := time.Now().Add(2 * time.Second)
	conn.SetWriteDeadline(deadline)
	if cur != nil {
		if _, err := conn.Write(cur); err != nil {
			return
		}
		s.sent.Add(1)
	}
	for time.Now().Before(deadline) {
		select {
		case f := <-s.q:
			if _, err := conn.Write(f); err != nil {
				return
			}
			s.sent.Add(1)
		default:
			return
		}
	}
}
