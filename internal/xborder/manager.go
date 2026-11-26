package xborder

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

// Manager owns the running collector + sender and swaps them when the
// xborder_log config changes, without restarting turnout-gateway.
//
// Restarting the gateway to apply a log setting would be the simpler path
// (it is what PUT /api/node/signal does), but a restart withdraws the
// watchdog's liveness address until it re-qualifies; with auto_failover on,
// the firewall would drop the whole office back to direct routing for that
// window. A logging knob must not be able to do that.
type Manager struct {
	base Options // APIAddr, Secret, Hostname, Pools; Emit/PollInterval are set per run

	mu       sync.Mutex
	rootCtx  context.Context
	cfg      config.XBorderLogConfig
	sender   *SyslogSender
	sendStop func() // cancels and waits for the sender
	coll     *Collector
	collStop func()
	since    time.Time

	seq atomic.Uint64
	// sendMu guards cur, the sender the collector currently emits into.
	// Separate from mu so Apply can wait for goroutines that emit.
	sendMu sync.RWMutex
	cur    *SyslogSender
}

// NewManager builds a manager. base supplies the mihomo clash-api address
// and secret, the hostname, and the configured pool names.
func NewManager(base Options) *Manager {
	return &Manager{base: base}
}

// Start applies cfg under ctx; later Apply calls reuse ctx. Errors are
// only possible for configs that failed validation.
func (m *Manager) Start(ctx context.Context, cfg config.XBorderLogConfig) error {
	m.mu.Lock()
	m.rootCtx = ctx
	m.mu.Unlock()
	return m.Apply(cfg)
}

// Apply makes the running state match cfg. Records queued for the old
// server are handed to the new sender, so changing the address does not
// lose the backlog. The collector restarts only when it is turned on or
// off or its poll interval changes — a restart forgets which short
// connections were still waiting for a sample.
func (m *Manager) Apply(cfg config.XBorderLogConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rootCtx == nil {
		m.cfg = cfg
		return nil
	}

	var next *SyslogSender
	if cfg.Enabled {
		cfg = cfg.WithDefaults()
		s, err := NewSyslogSender(SyslogConfig{
			Address: cfg.Address, Framing: cfg.Framing, Facility: cfg.Facility,
			AppName: cfg.AppName, Hostname: m.base.Hostname, QueueSize: cfg.QueueSize,
		})
		if err != nil {
			return err
		}
		next = s
	}

	collectorChange := !cfg.Enabled || m.coll == nil || cfg.PollInterval != m.cfg.PollInterval
	if collectorChange && m.collStop != nil {
		m.collStop()
		m.coll, m.collStop = nil, nil
	}

	// Point the collector at the new sender first. emit holds sendMu while
	// it enqueues, so once the swap returns nothing can still be writing
	// into the old queue. Then stop the old sender (it flushes for up to 2s
	// to its own server) and move what it still holds into the new one.
	m.sendMu.Lock()
	m.cur = next
	m.sendMu.Unlock()
	var backlog []Record
	if m.sendStop != nil {
		m.sendStop()
		backlog = m.sender.Drain()
		m.sender, m.sendStop = nil, nil
	}

	wasEnabled := m.cfg.Enabled
	m.cfg = cfg
	if !cfg.Enabled {
		if len(backlog) > 0 {
			slog.Warn("xborder: access log disabled; discarding unsent records", "count", len(backlog))
		}
		if wasEnabled {
			slog.Info("xborder: access log disabled")
		}
		m.since = time.Time{}
		return nil
	}

	for _, r := range backlog {
		next.Enqueue(r)
	}
	m.sender = next
	m.sendStop = run(m.rootCtx, next.Run)
	if m.coll == nil {
		o := m.base
		o.PollInterval = cfg.PollInterval
		o.Emit = m.emit
		o.Seq = &m.seq
		m.coll = NewCollector(o)
		m.collStop = run(m.rootCtx, m.coll.Run)
	}
	if !wasEnabled || m.since.IsZero() {
		m.since = time.Now()
	}
	slog.Info("xborder: access log enabled", "addr", cfg.Address, "framing", cfg.Framing,
		"facility", cfg.Facility, "poll_interval", cfg.PollInterval, "carried_over", len(backlog))
	return nil
}

func (m *Manager) emit(r Record) {
	m.sendMu.RLock()
	defer m.sendMu.RUnlock()
	if m.cur != nil {
		m.cur.Enqueue(r) // never blocks
	}
}

// run starts fn in a goroutine under a child of ctx and returns a func that
// cancels it and waits for it to return.
func run(ctx context.Context, fn func(context.Context)) func() {
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn(cctx)
	}()
	return func() {
		cancel()
		<-done
	}
}

// Status is what GET /api/xborder-log reports about the running sink.
type Status struct {
	Running bool `json:"running"`
	// Since is when logging was last turned on in this process.
	Since *time.Time `json:"since,omitempty"`
	// Seq is the last record number handed out; a receiver comparing it to
	// the last seq it stored can see how far behind it is.
	Seq uint64 `json:"seq"`
	SenderStatus
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{Seq: m.seq.Load()}
	if m.sender != nil {
		st.Running = true
		st.Since = timePtr(m.since)
		st.SenderStatus = m.sender.Status()
	}
	return st
}
