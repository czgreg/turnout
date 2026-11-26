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
	"sync"
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
// The queue holds records, not formatted frames, so a sender replaced by a
// config change can hand its backlog to the next one (see Drain) and those
// records go out in the new format to the new server.
//
// Plain TCP has no acknowledgement. A record written into the socket just
// before the server dies can be lost without an error; the receiver sees
// it as a gap in seq.
type SyslogSender struct {
	cfg      SyslogConfig
	facility int
	host     string
	pid      int
	q        chan Record

	sent      atomic.Uint64
	dropped   atomic.Uint64
	connected atomic.Bool

	errMu   sync.Mutex
	lastErr string
	errAt   time.Time
	sentAt  time.Time

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
		q:        make(chan Record, cfg.QueueSize),
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

// Enqueue queues r. Never blocks; safe for concurrent use.
func (s *SyslogSender) Enqueue(r Record) {
	for {
		select {
		case s.q <- r:
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

// Drain removes and returns everything still queued. Call only after Run
// has returned.
func (s *SyslogSender) Drain() []Record {
	var out []Record
	for {
		select {
		case r := <-s.q:
			out = append(out, r)
		default:
			return out
		}
	}
}

func (s *SyslogSender) frame(r Record) ([]byte, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	sev := sevInfo
	if r.Event == EventDialError {
		sev = sevWarning
	}
	msg := fmt.Sprintf("<%d>1 %s %s %s %d %s - %s",
		s.facility*8+sev, s.now().Format("2006-01-02T15:04:05.000000Z07:00"),
		s.host, s.cfg.AppName, s.pid, r.Event, body)
	if s.cfg.Framing == "octet-counting" {
		return []byte(strconv.Itoa(len(msg)) + " " + msg), nil
	}
	return []byte(msg + "\n"), nil
}

// SenderStatus is a point-in-time view for the API.
type SenderStatus struct {
	Connected   bool      `json:"connected"`
	Sent        uint64    `json:"sent"`
	Dropped     uint64    `json:"dropped"`
	Queued      int       `json:"queued"`
	QueueSize   int       `json:"queue_size"`
	LastSentAt  time.Time `json:"last_sent_at,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	LastErrorAt time.Time `json:"last_error_at,omitempty"`
}

func (s *SyslogSender) Status() SenderStatus {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	return SenderStatus{
		Connected:   s.connected.Load(),
		Sent:        s.sent.Load(),
		Dropped:     s.dropped.Load(),
		Queued:      len(s.q),
		QueueSize:   cap(s.q),
		LastSentAt:  s.sentAt,
		LastError:   s.lastErr,
		LastErrorAt: s.errAt,
	}
}

func (s *SyslogSender) setErr(err error) {
	s.errMu.Lock()
	s.lastErr, s.errAt = err.Error(), time.Now()
	s.errMu.Unlock()
}

func (s *SyslogSender) markSent() {
	s.sent.Add(1)
	s.errMu.Lock()
	s.sentAt = time.Now()
	s.errMu.Unlock()
}

// Run sends until ctx is cancelled, then makes one short attempt to flush
// what is still queued to the connection it already has. Anything left is
// available through Drain.
//
// It connects as soon as it starts and re-checks the connection every 10s
// while idle, so Status().Connected reflects whether the server is
// reachable even when no cross-border traffic is flowing.
func (s *SyslogSender) Run(ctx context.Context) {
	var conn net.Conn
	var cur []byte
	var curRec *Record
	backoff := time.Second
	failing := false
	idle := time.NewTicker(10 * time.Second)
	defer idle.Stop()
	var lastDropped uint64
	lastReport := time.Now()

	defer func() {
		s.connected.Store(false)
		if conn == nil {
			if curRec != nil {
				s.Enqueue(*curRec) // keep it for Drain
			}
			return
		}
		s.flush(conn, cur, curRec)
		conn.Close()
	}()

	for {
		if conn != nil && peerClosed(conn) {
			conn.Close()
			conn = nil
			s.connected.Store(false)
		}
		if conn == nil {
			dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			c, err := s.dial(dctx, s.cfg.Address)
			cancel()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				s.setErr(err)
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
			s.connected.Store(true)
			backoff = time.Second
			if failing {
				slog.Info("xborder: syslog server reachable again", "addr", s.cfg.Address, "queued", len(s.q))
				failing = false
			} else {
				slog.Info("xborder: connected to syslog server", "addr", s.cfg.Address)
			}
		}
		if cur == nil {
			select {
			case <-ctx.Done():
				return
			case r := <-s.q:
				f, err := s.frame(r)
				if err != nil {
					slog.Error("xborder: marshal record", "err", err)
					continue
				}
				cur, curRec = f, &r
			case <-idle.C:
				if d := s.dropped.Load(); d != lastDropped && time.Since(lastReport) >= time.Minute {
					slog.Warn("xborder: records dropped, send queue was full",
						"dropped_total", d, "dropped_since_last_report", d-lastDropped,
						"sent_total", s.sent.Load(), "queued", len(s.q))
					lastDropped, lastReport = d, time.Now()
				}
				continue // loop top re-checks the connection
			}
		}
		// The record may have waited in select for a long time; the server
		// can have gone away meanwhile, and the first write into a closed
		// connection still "succeeds".
		if peerClosed(conn) {
			conn.Close()
			conn = nil
			s.connected.Store(false)
			continue
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(cur); err != nil {
			s.setErr(err)
			slog.Warn("xborder: syslog write failed, reconnecting", "addr", s.cfg.Address, "err", err)
			conn.Close()
			conn = nil
			s.connected.Store(false)
			continue // retry cur on a fresh connection
		}
		s.markSent()
		cur, curRec = nil, nil
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

// flush writes cur and whatever is queued, giving up after 2s. What it
// could not send stays queued for Drain.
func (s *SyslogSender) flush(conn net.Conn, cur []byte, curRec *Record) {
	deadline := time.Now().Add(2 * time.Second)
	conn.SetWriteDeadline(deadline)
	if cur != nil {
		if _, err := conn.Write(cur); err != nil {
			s.Enqueue(*curRec)
			return
		}
		s.markSent()
	}
	for time.Now().Before(deadline) {
		select {
		case r := <-s.q:
			f, err := s.frame(r)
			if err != nil {
				continue
			}
			if _, err := conn.Write(f); err != nil {
				s.Enqueue(r)
				return
			}
			s.markSent()
		default:
			return
		}
	}
}
