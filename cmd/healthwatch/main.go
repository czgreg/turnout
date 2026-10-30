// Command healthwatch samples the gateway's observable state once per
// interval and appends one JSON object per sample to a daily JSONL file.
//
// Why a separate process rather than another API endpoint: the records must
// survive a gateway restart (a restart is exactly when the interesting
// failures happen — see the 2026-10-24 startup incidents), and writing them
// must not depend on the control plane being healthy. The sampler itself is
// stateless apart from its in-memory journal cursor and mtime baseline; every
// field is re-derived from the APIs, /proc, the rendered config, and
// journald each tick.
//
// What it records (one line per tick, see Sample):
//   - /healthz: data-path assertion verdict + failing check names
//   - /api/status: pool size, K, tier-1 count, last scoring/refresh times
//   - /api/nodes/health: in-pool nodes with RTT/jitter/fail/probe counts
//   - /api/pool/transitions: churn count in this interval (the optimisation
//     signal) plus the 5m/1h/24h windows
//   - rendered config: mtime/bytes, fallback group count, per-term rule count
//   - journald: hot reloads/failures, scored rounds, warm-up skips, warning
//     and error counts for both units
//   - DNS: one rotating whitelisted domain resolved through the gateway's
//     own resolver (this is what a terminal experiences)
//   - direct TCP to 1.1.1.1:853/443 and 8.8.8.8:443 (the 2026-10-24 outage
//     was these paths being blocked while the pool stayed healthy)
//   - one active proxy delay request through the probe terminal's pair group
//   - resources: mihomo/gateway RSS, load1, available memory, disk
//
// Usage:
//
//	turnout-healthwatch --config /etc/turnout/gateway.yaml
//	turnout-healthwatch --summary --summary-hours 24
//
// Records land in /var/lib/turnout/health/health-YYYY-MM-DD.jsonl.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/turnout-gateway/turnout-gateway/internal/config"
)

func main() {
	var (
		cfgPath   = flag.String("config", "/etc/turnout/gateway.yaml", "gateway.yaml (root-readable; used for ingress IP, config path, preload domains)")
		apiAddr   = flag.String("api", "https://127.0.0.1:18080", "turnout-gateway control-plane API base URL")
		apiCert   = flag.String("api-tls-cert", config.DefaultAPITLSDir+"/cert.pem", "certificate file the gateway wrote; its public key is pinned for every https API call (empty = system trust)")
		clashAddr = flag.String("clash", "http://127.0.0.1:9090", "mihomo clash-api base URL")
		interval  = flag.Duration("interval", 60*time.Second, "sampling interval")
		outDir    = flag.String("out", "/var/lib/turnout/health", "JSONL output directory")
		retain    = flag.Duration("retain", 30*24*time.Hour, "delete JSONL files older than this")
		probeIP   = flag.String("probe-ip", os.Getenv("HEALTHWATCH_PROBE_IP"), "terminal IP to sample the per-terminal assignment for (optional)")
		apiToken  = flag.String("api-token", os.Getenv("HEALTHWATCH_API_TOKEN"), "bearer token for the control-plane API (when api.token is set)")
		summary   = flag.Bool("summary", false, "read recorded JSONL and print an aggregate report instead of sampling")
		sumHours  = flag.Int("summary-hours", 24, "window for --summary")
	)
	flag.Parse()

	if *summary {
		if err := printSummary(*outDir, time.Duration(*sumHours)*time.Hour, os.Stdout); err != nil {
			log.Fatalf("healthwatch: summary: %v", err)
		}
		return
	}

	cfg := loadGatewayConfig(*cfgPath)
	if cfg != nil && !cfg.API.TLS.AutoManaged() && *apiCert == config.DefaultAPITLSDir+"/cert.pem" {
		// Operator-provided certificate: pin the file gateway.yaml names,
		// not the auto-managed default path (which does not exist then).
		*apiCert, _ = cfg.API.TLS.Paths()
	}
	if strings.HasPrefix(*apiAddr, "https://") && *apiCert != "" {
		if err := pinAPI(*apiCert); err != nil {
			log.Fatalf("healthwatch: pin %s: %v", *apiCert, err)
		}
	}
	s := &sampler{
		api:       strings.TrimRight(*apiAddr, "/"),
		clash:     strings.TrimRight(*clashAddr, "/"),
		probeIP:   *probeIP,
		token:     *apiToken,
		cfgPath:   *cfgPath,
		outDir:    *outDir,
		preload:   probeDomains(cfg),
		dnsAddr:   dnsListenAddr(cfg),
		confPath:  configPath(cfg),
		startedAt: time.Now(),
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatalf("healthwatch: mkdir %s: %v", *outDir, err)
	}
	prune(*outDir, *retain)

	log.Printf("healthwatch: sampling every %s → %s (dns=%s probe_ip=%q)", *interval, *outDir, s.dnsAddr, s.probeIP)

	// First sample immediately: a restart is when state matters most and an
	// operator reading the log should not wait a full interval for the first line.
	s.sampleAndWrite(ctx, false, 0)

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	lastSample := time.Now()
	lastDay := time.Now().Format("2006-01-02")
	for {
		select {
		case <-ctx.Done():
			log.Printf("healthwatch: stopping")
			return
		case <-tick.C:
			now := time.Now()
			day := now.Format("2006-01-02")
			if day != lastDay {
				prune(*outDir, *retain)
				lastDay = day
			}
			s.sampleAndWrite(ctx, true, now.Sub(lastSample))
			lastSample = now
		}
	}
}

// sampler holds the only state the process keeps between ticks: the journal
// cursor (derived from the previous tick time), the last config mtime, and
// the terminal IP to inspect.
type sampler struct {
	api       string
	clash     string
	probeIP   string
	token     string
	cfgPath   string
	outDir    string
	preload   []string
	dnsAddr   string
	confPath  string
	startedAt time.Time

	lastMtime   time.Time
	domainIndex int
}

func (s *sampler) sampleAndWrite(ctx context.Context, delta bool, window time.Duration) {
	now := time.Now()
	if !delta {
		// First sample has no interval: report the last 2 minutes of journal
		// so a reload that happened just before start is still captured.
		window = 2 * time.Minute
	}
	sample := s.sample(ctx, now, window)
	sample.TS = now.Format(time.RFC3339)
	path := filepath.Join(s.outDir, "health-"+now.Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("healthwatch: open %s: %v", path, err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	if err := enc.Encode(sample); err != nil {
		log.Printf("healthwatch: write: %v", err)
	}
}

// loadGatewayConfig is best-effort: the sampler still works with flags and
// defaults when the yaml is unreadable (e.g. run as a non-root user).
func loadGatewayConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		log.Printf("healthwatch: config %s: %v (using flags/defaults)", path, err)
		return nil
	}
	return cfg
}

func dnsListenAddr(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	if v := cfg.DataPlane.DNS.Listen; v != "" {
		return v
	}
	if ip := cfg.Node.IngressIP; ip != "" {
		return ip + ":53"
	}
	return ""
}

func configPath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return cfg.DataPlane.ConfigPath
}

// probeDomains rotates through the operator's preload list (already curated
// from the whitelist) so consecutive samples do not all hit one cache entry.
// Falls back to a few high-traffic destinations when preload is empty.
func probeDomains(cfg *config.Config) []string {
	if cfg != nil && len(cfg.DataPlane.DNS.PreloadDomains) > 0 {
		return append([]string(nil), cfg.DataPlane.DNS.PreloadDomains...)
	}
	return []string{"www.youtube.com", "claude.ai", "api.anthropic.com", "github.com", "www.google.com"}
}

func (s *sampler) nextDomain() string {
	if len(s.preload) == 0 {
		return ""
	}
	d := s.preload[s.domainIndex%len(s.preload)]
	s.domainIndex++
	return d
}
