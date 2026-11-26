package xborder

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"time"
)

// Options wires a Collector. APIAddr/Secret are mihomo's clash-api; Emit
// receives finished records on the collector goroutine (it must not block
// for long — the syslog sender's Enqueue never does).
type Options struct {
	APIAddr      string
	Secret       string
	Hostname     string
	Pools        []string // configured named pool names (excluding default-pool)
	PollInterval time.Duration
	Emit         func(Record)

	// Test seams. Zero values select the production implementation.
	HTTPClient *http.Client
	OrigDsts   func(ctx context.Context) (map[string]string, error)
	Now        func() time.Time
}

type Collector struct {
	o     Options
	pools []string
	seq   uint64

	live      map[string]*trackedConn // mihomo conn ID → state
	liveByKey map[connKey]string
	pending   map[connKey]pendingLine // established lines no sample has claimed yet
	// groupDirect records, per proxy group, whether the last connection
	// sampled through it went out DIRECT. An empty named pool renders as a
	// select stub on DIRECT (internal/mihomo/groups.go), and its dial
	// failures must not be logged as cross-border.
	groupDirect map[string]bool

	pollFailing bool
}

type trackedConn struct {
	rec      Record
	key      connKey
	start    time.Time
	lastSeen time.Time
}

type pendingLine struct {
	l  logLine
	at time.Time
}

func NewCollector(o Options) *Collector {
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.HTTPClient == nil {
		// Proxy: nil — clash-api is on loopback; never route it through
		// an environment proxy.
		o.HTTPClient = &http.Client{Transport: &http.Transport{Proxy: nil}}
	}
	if o.OrigDsts == nil {
		o.OrigDsts = ssOrigDsts
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	pools := append([]string(nil), o.Pools...)
	sort.Slice(pools, func(i, j int) bool { return len(pools[i]) > len(pools[j]) })
	return &Collector{
		o:           o,
		pools:       pools,
		live:        make(map[string]*trackedConn),
		liveByKey:   make(map[connKey]string),
		pending:     make(map[connKey]pendingLine),
		groupDirect: make(map[string]bool),
	}
}

// pendingGrace is how long an established line waits for a sample to claim
// it before it is emitted on its own (the connection closed between two
// samples). Must exceed one poll interval plus the log-delivery delay.
func (c *Collector) pendingGrace() time.Duration { return 2*c.o.PollInterval + 3*time.Second }

func (c *Collector) Run(ctx context.Context) {
	lines := make(chan timedLine, 4096)
	go c.streamLogs(ctx, lines)
	t := time.NewTicker(c.o.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case tl := <-lines:
			c.onLine(tl.l, tl.at)
		case <-t.C:
			c.poll(ctx)
		}
	}
}

type timedLine struct {
	l  logLine
	at time.Time
}

// streamLogs follows mihomo's /logs stream, reconnecting with backoff.
// Lines produced while disconnected are lost; mihomo does not replay.
func (c *Collector) streamLogs(ctx context.Context, out chan<- timedLine) {
	backoff := time.Second
	failing := false
	for ctx.Err() == nil {
		connected, err := c.readLogStream(ctx, out, func() {
			if failing {
				slog.Info("xborder: mihomo log stream reconnected")
				failing = false
			}
			backoff = time.Second
		})
		if ctx.Err() != nil {
			return
		}
		if !failing {
			slog.Warn("xborder: mihomo log stream lost; short connections and dial failures are not recorded until it reconnects",
				"err", err, "was_connected", connected)
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
	}
}

// readLogStream consumes one /logs stream until it ends. onConnect runs
// once the server has accepted the request.
func (c *Collector) readLogStream(ctx context.Context, out chan<- timedLine, onConnect func()) (bool, error) {
	req, err := c.newReq(ctx, "/logs?level=info")
	if err != nil {
		return false, err
	}
	resp, err := c.o.HTTPClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("GET /logs: %s", resp.Status)
	}
	onConnect()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var ev struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil {
			continue
		}
		l, ok := parseLogLine(ev.Payload)
		if !ok {
			continue
		}
		select {
		case out <- timedLine{l: l, at: c.o.Now()}:
		case <-ctx.Done():
			return true, ctx.Err()
		}
	}
	if err := sc.Err(); err != nil {
		return true, err
	}
	return true, fmt.Errorf("GET /logs: stream ended")
}

func (c *Collector) newReq(ctx context.Context, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+c.o.APIAddr+path, nil)
	if err != nil {
		return nil, err
	}
	if c.o.Secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.o.Secret)
	}
	return req, nil
}

func (c *Collector) onLine(l logLine, at time.Time) {
	if l.dialErr {
		if !isOverseasNode(l.group) || c.groupDirect[l.group] {
			return
		}
		c.emit(c.dialErrorRecord(l, at))
		return
	}
	if !isOverseasNode(l.node) {
		return
	}
	if id, ok := c.liveByKey[l.key]; ok {
		if t := c.live[id]; t != nil && !t.rec.Collect.Logged {
			t.rec.Collect.Logged = true
			return
		}
	}
	if old, ok := c.pending[l.key]; ok {
		// A second connection on the same client port before the first was
		// claimed: the first must have closed already.
		c.emit(c.logOnlyRecord(old.l, old.at))
	}
	c.pending[l.key] = pendingLine{l: l, at: at}
}

// apiConn is the subset of a mihomo /connections entry we use.
type apiConn struct {
	ID       string `json:"id"`
	Metadata struct {
		Network         string `json:"network"`
		Type            string `json:"type"`
		SourceIP        string `json:"sourceIP"`
		SourcePort      string `json:"sourcePort"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
		Host            string `json:"host"`
		SniffHost       string `json:"sniffHost"`
	} `json:"metadata"`
	Upload      int64     `json:"upload"`
	Download    int64     `json:"download"`
	Start       time.Time `json:"start"`
	Chains      []string  `json:"chains"`
	Rule        string    `json:"rule"`
	RulePayload string    `json:"rulePayload"`
}

func (c *Collector) fetchConnections(ctx context.Context) ([]apiConn, error) {
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := c.newReq(pctx, "/connections")
	if err != nil {
		return nil, err
	}
	resp, err := c.o.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /connections: %s", resp.Status)
	}
	var body struct {
		Connections []apiConn `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Connections, nil
}

func (c *Collector) poll(ctx context.Context) {
	conns, err := c.fetchConnections(ctx)
	if ctx.Err() != nil {
		return // shutting down; not a sampling failure
	}
	if err != nil {
		// Keep every live connection and pending line as-is: without a
		// sample there is no evidence anything closed.
		if !c.pollFailing {
			slog.Warn("xborder: /connections sample failed", "err", err)
			c.pollFailing = true
		}
		return
	}
	if c.pollFailing {
		slog.Info("xborder: /connections sampling recovered")
		c.pollFailing = false
	}
	now := c.o.Now()
	seen := make(map[string]bool, len(conns))
	var needDst []*trackedConn
	for i := range conns {
		ac := &conns[i]
		if len(ac.Chains) >= 2 {
			c.groupDirect[ac.Chains[len(ac.Chains)-1]] = ac.Chains[0] == "DIRECT"
		}
		// Only terminal traffic: TProxy is the one inbound terminals reach.
		// Inner (gateway DoH via dns-out) and the loopback HTTP/SOCKS probe
		// inbounds are the gateway's own connections.
		if ac.ID == "" || ac.Metadata.Type != "TProxy" || len(ac.Chains) == 0 || !isOverseasNode(ac.Chains[0]) {
			continue
		}
		seen[ac.ID] = true
		if t, ok := c.live[ac.ID]; ok {
			t.lastSeen = now
			t.rec.Traffic.UpBytes, t.rec.Traffic.DownBytes = ac.Upload, ac.Download
			continue
		}
		t := c.newTracked(ac, now)
		c.live[ac.ID] = t
		c.liveByKey[t.key] = ac.ID
		if p, ok := c.pending[t.key]; ok {
			delete(c.pending, t.key)
			t.rec.Collect.Logged = true
			if t.rec.Route.Rule == "" {
				t.rec.Route.Rule, t.rec.Route.RulePayload = p.l.rule, p.l.rulePayload
			}
		}
		if t.rec.Dst.IP == "" && t.key.network == "tcp" {
			needDst = append(needDst, t)
		}
	}
	if len(needDst) > 0 {
		if m, err := c.o.OrigDsts(ctx); err == nil {
			for _, t := range needDst {
				t.rec.Dst.IP = m[srcKey(t.rec.Src.IP, t.rec.Src.Port)]
			}
		} else {
			slog.Debug("xborder: ss lookup failed", "err", err)
		}
	}
	for id, t := range c.live {
		if seen[id] {
			continue
		}
		delete(c.live, id)
		if c.liveByKey[t.key] == id {
			delete(c.liveByKey, t.key)
		}
		if _, ok := c.pending[t.key]; ok && !t.rec.Collect.Logged {
			delete(c.pending, t.key)
			t.rec.Collect.Logged = true
		}
		c.emit(c.closeRecord(t))
	}
	for k, p := range c.pending {
		if now.Sub(p.at) >= c.pendingGrace() {
			delete(c.pending, k)
			c.emit(c.logOnlyRecord(p.l, p.at))
		}
	}
}

func (c *Collector) newTracked(ac *apiConn, now time.Time) *trackedConn {
	md := &ac.Metadata
	sport, _ := strconv.Atoi(md.SourcePort)
	dport, _ := strconv.Atoi(md.DestinationPort)
	start := ac.Start
	if start.IsZero() {
		start = now
	}
	node := ac.Chains[0]
	group := ""
	if len(ac.Chains) >= 2 {
		group = ac.Chains[len(ac.Chains)-1]
	}
	host := md.Host
	if host == "" {
		host = md.SniffHost
	}
	t := &trackedConn{
		key:      connKey{network: md.Network, srcIP: md.SourceIP, srcPort: sport, dstPort: dport},
		start:    start,
		lastSeen: now,
	}
	t.rec = Record{
		Conn: ConnFields{ID: ac.ID, Network: md.Network, Start: fmtTS(start)},
		Src:  SrcFields{IP: md.SourceIP, Port: sport},
		Dst:  DstFields{Host: host, SniffHost: md.SniffHost, IP: md.DestinationIP, Port: dport},
		Route: RouteFields{
			Rule: ac.Rule, RulePayload: ac.RulePayload,
			Pool: poolOf(group, c.pools), Group: group,
			Chains: append([]string(nil), ac.Chains...),
		},
		Egress:  EgressFields{Node: node, Region: regionOf(node)},
		Traffic: &TrafficFields{UpBytes: ac.Upload, DownBytes: ac.Download},
		Result:  ResultFields{Status: "ok"},
		Collect: CollectFields{Tracked: true},
	}
	return t
}

func (c *Collector) closeRecord(t *trackedConn) Record {
	r := t.rec
	r.Event = EventClose
	end := t.lastSeen
	if end.Before(t.start) {
		end = t.start
	}
	r.Conn.End = fmtTS(end)
	r.Conn.DurationMs = end.Sub(t.start).Milliseconds()
	// Counts are from the last sample: whatever moved after it is missing.
	r.Traffic.BytesFinal = false
	return r
}

// lineBase fills the fields a log line alone can provide.
func (c *Collector) lineBase(l logLine, at time.Time) Record {
	r := Record{
		Conn: ConnFields{
			ID:      fmt.Sprintf("log-%s-%d-%d", l.key.srcIP, l.key.srcPort, at.UnixMilli()),
			Network: l.key.network,
			Start:   fmtTS(at),
		},
		Src: SrcFields{IP: l.key.srcIP, Port: l.key.srcPort},
		Dst: DstFields{Host: l.host, Port: l.key.dstPort},
		Route: RouteFields{
			Rule: l.rule, RulePayload: l.rulePayload,
			Pool: poolOf(l.group, c.pools), Group: l.group,
		},
		Collect: CollectFields{Logged: true},
	}
	if a, err := netip.ParseAddr(l.host); err == nil {
		r.Dst.Host, r.Dst.IP = "", a.Unmap().String()
	}
	return r
}

// logOnlyRecord is a connection that opened and closed between two
// samples: no ID, byte counts or end time are known.
func (c *Collector) logOnlyRecord(l logLine, at time.Time) Record {
	r := c.lineBase(l, at)
	r.Event = EventClose
	if l.group != "" {
		r.Route.Chains = []string{l.node, l.group}
	} else {
		r.Route.Chains = []string{l.node}
	}
	r.Egress = EgressFields{Node: l.node, Region: regionOf(l.node)}
	r.Traffic = &TrafficFields{}
	r.Result = ResultFields{Status: "ok"}
	return r
}

const maxErrLen = 512

func (c *Collector) dialErrorRecord(l logLine, at time.Time) Record {
	r := c.lineBase(l, at)
	r.Event = EventDialError
	r.Route.Chains = []string{l.group}
	e := l.err
	if len(e) > maxErrLen {
		e = e[:maxErrLen]
	}
	r.Result = ResultFields{Status: "dial_error", Error: e}
	return r
}

func (c *Collector) emit(r Record) {
	c.seq++
	r.Schema = Schema
	r.Seq = c.seq
	r.TS = fmtTS(c.o.Now())
	r.Gateway.Hostname = c.o.Hostname
	if r.Route.Chains == nil {
		r.Route.Chains = []string{}
	}
	c.o.Emit(r)
}

// ssOrigDsts lists established TCP sockets. Run only when a newly seen
// connection lacks mihomo's destinationIP, so it is not forked every poll.
func ssOrigDsts(ctx context.Context) (map[string]string, error) {
	sctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(sctx, "ss", "-Htn", "state", "established").Output()
	if err != nil {
		return nil, err
	}
	return parseSS(string(out)), nil
}
