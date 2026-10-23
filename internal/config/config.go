// Package config defines the on-disk yaml schema (gateway.yaml) and applies
// defaults at load time. Schema lives in this single file — keep it that way
// so new fields are easy to find by reading top-to-bottom.
//
// History: turnout-gateway started as a sing-box sidecar; the legacy schema
// nested all engine fields under `singbox:`. After the mihomo cutover and
// the sing-box renderer was removed, the top-level block was renamed to
// `data_plane:` and three new sibling blocks were added — `node_qualify`,
// `pools` — that used to be buried under `singbox.url_test.*`. The old
// `singbox:` and `urltest.watchdog:` blocks are no longer accepted.
package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	API           APIConfig           `yaml:"api"`
	Subscribe     SubscribeConfig     `yaml:"subscribe"`
	Subscriptions []SubscriptionEntry `yaml:"subscriptions"`
	Node          NodeConfig          `yaml:"node"`
	DataPlane     DataPlaneConfig     `yaml:"data_plane"`

	// NodeQualify drives the NodeScorer goroutine that dynamically manages
	// default-pool membership: each ScoringInterval the scorer probes every
	// candidate, applies the thresholds + probe checks, and hot-reloads
	// mihomo when the qualified set changes.
	NodeQualify NodeQualifyConfig `yaml:"node_qualify"`

	// Pools lists named select groups that get rendered alongside the
	// default default-pool. Each pool is gated by `requires_passing` (probe
	// names from NodeQualify.Probes that must all pass) and routes the
	// listed `rule_sets` via mihomo rules. Used to segregate sites with
	// special needs (e.g. openai-pool for ChatGPT/Claude — only nodes
	// passing chatgpt.com / claude.ai probes qualify).
	Pools []PoolConfig `yaml:"pools"`

	// Capacity holds the single-node user-capacity ceiling measured by an
	// offline stress test (scripts/stress.sh). These are STATIC operator-
	// supplied numbers — turnout-gateway does not measure them at runtime
	// (you can't load-test live production). Surfaced in /api/status so
	// operators can compare current load against the known ceiling.
	Capacity CapacityConfig `yaml:"capacity"`

	// LoadBalance tunes how overseas (default-pool-bound) traffic is spread.
	// Default zero value = per-destination (consistent-hashing) as before.
	LoadBalance LoadBalanceConfig `yaml:"load_balance"`

	// Notifications drives outbound alerts (currently Lark webhook only).
	// Disabled by default — operator must set `notifications.enabled: true`
	// AND configure a webhook target via API or yaml. Events that flow
	// through this layer: pool composition changes, emergency evictions,
	// node degradation crossings, webhook health.
	Notifications NotificationsConfig `yaml:"notifications"`

	// Watchdog is the bypass-role health reporter. It self-checks the data
	// path and, when unhealthy, withdraws the liveness address so the
	// upstream firewall's IP-Link probe goes Down and traffic falls back to
	// direct routing. See the type doc for why this exists at all.
	Watchdog WatchdogConfig `yaml:"watchdog"`
}

// NotificationsConfig is the user-facing notification settings. Webhook
// secrets are stored separately at runtime — yaml carries the URL +
// signing flag only, never the actual secret.
type NotificationsConfig struct {
	// Enabled gates the entire notification subsystem. false = scorer
	// events still log to slog, but no webhook calls fire and no local
	// JSONL log is written. Default false (operator must opt in).
	Enabled bool `yaml:"enabled"`

	// Lark holds the Lark/Feishu webhook configuration. Secrets are NOT
	// stored in yaml — set via POST /api/notifications/lark.
	Lark LarkConfig `yaml:"lark"`

	// LocalLogPath is the JSONL audit trail of every notification attempt
	// (before the webhook call), regardless of webhook delivery success.
	// Lets operators reconstruct "what was the system trying to tell me"
	// even when Lark itself was unreachable. Default
	// /var/lib/turnout/notifications.log (writable per systemd ReadWritePaths).
	LocalLogPath string `yaml:"local_log_path"`

	// DedupWindow collapses repeated (node, event_type) notifications
	// within this window into one. Default 5m — long enough to suppress
	// BGP-flap spam without hiding genuine repeated incidents.
	DedupWindow time.Duration `yaml:"dedup_window"`

	// AggregationWindow batches multiple events occurring within this
	// window into a single Lark message. Default 30s — short enough that
	// urgency isn't lost, long enough to coalesce a 5-node simultaneous
	// flap. Aggregation NEVER applies to "urgent" severity.
	AggregationWindow time.Duration `yaml:"aggregation_window"`

	// PerNodeRateLimitPerHour caps how many "info"-tier notifications a
	// single node can generate per hour after dedup. Default 4 — covers
	// real flapping without becoming a firehose. Urgent events bypass
	// this limit.
	PerNodeRateLimitPerHour int `yaml:"per_node_rate_limit_per_hour"`

	// RetryAttempts on webhook 5xx / network errors. Default 3 with
	// exponential backoff (1s, 2s, 4s). Failed attempts are still logged
	// locally; urgent events that exhaust retries get re-attempted on
	// the next scoring round (best-effort recovery).
	RetryAttempts int `yaml:"retry_attempts"`

	// InstanceName identifies which gateway sent a notification, surfaced
	// in the Lark message header (e.g. "turnout-gateway@92"). With multiple
	// nodes (89 / 92) posting to the same Lark channel, the operator can't
	// otherwise tell which one a pool-flap or node-dead alert came from.
	// Defaults to the OS hostname when left empty.
	InstanceName string `yaml:"instance_name"`
}

// LarkConfig is the Lark/Feishu webhook target. URL is yaml-stored; the
// signing secret is runtime-only (POST /api/notifications/lark).
type LarkConfig struct {
	// WebhookURL is the full Lark bot webhook URL (incl. token).
	// Empty = Lark output disabled even when Notifications.Enabled=true.
	WebhookURL string `yaml:"webhook_url"`

	// SignatureRequired turns on Lark's HMAC-SHA256 signing. When true,
	// runtime must have a secret set (via API); without one,
	// notifications fail-closed (logged locally, never POSTed). Strongly
	// recommended for any production webhook — default true.
	SignatureRequired bool `yaml:"signature_required"`

	// SecretFile is the on-disk path holding the Lark webhook signing
	// secret. POST /api/notifications/lark writes it (chmod 0600);
	// Notifier reads at startup + reload. Default
	// /var/lib/turnout/lark-secret. Kept separate from yaml so secrets
	// never end up in version control / log dumps.
	SecretFile string `yaml:"secret_file"`
}

// CapacityConfig records the stress-tested single-node ceiling. Update it
// after each re-run of scripts/stress.sh; bump measured_with when the
// binary or mihomo version changes (those invalidate the numbers).
type CapacityConfig struct {
	// SustainedMaxUsers is the concurrent-user count the node carries with
	// mihomo CPU < ~50% and no latency spike. Safe operating ceiling.
	SustainedMaxUsers int `yaml:"sustained_max_users"`
	// DegradedMaxUsers is where latency starts to spike but the node still
	// functions. Hard ceiling; do not exceed.
	DegradedMaxUsers int `yaml:"degraded_max_users"`
	// MeasuredAt is the date the stress test was run (free-form, e.g.
	// "2026-06-08"). Audit aid.
	MeasuredAt string `yaml:"measured_at"`
	// MeasuredWith is the gateway version / mihomo version the test ran
	// against (e.g. "bf6e610 / mihomo v1.19.26"). When the running version
	// differs, the numbers are stale — re-test.
	MeasuredWith string `yaml:"measured_with"`
}

type APIConfig struct {
	Listen string `yaml:"listen"`
	Token  string `yaml:"token"`
	// AllowFrom is a legacy/additive source-CIDR accept list rendered into
	// nft.conf by install.sh (NOT enforced in Go; the process still binds
	// Listen as given). The nft policy denies the diverted subnet and accepts other
	// sources by default, so this list is normally redundant.
	//
	// The fixed the diverted subnet deny is independent of this list. Token remains
	// the application-layer protection and should be configured when Listen
	// is exposed beyond loopback.
	// NEVER include the tun0 client_subnet here; those are untrusted
	// end-user terminals.
	AllowFrom []string `yaml:"allow_from,omitempty"`
}

type SubscribeConfig struct {
	RefreshInterval  time.Duration `yaml:"refresh_interval"`
	RefreshOnStartup bool          `yaml:"refresh_on_startup"`
	HTTPTimeout      time.Duration `yaml:"http_timeout"`
	UserAgent        string        `yaml:"user_agent"`
}

type SubscriptionEntry struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Format  string `yaml:"format"` // auto | clash | singbox | uri | sip008
	Enabled bool   `yaml:"enabled"`
	// UserAgent overrides Subscribe.UserAgent for this subscription only.
	// Different airports gate by UA in incompatible ways — set this per
	// subscription to whatever UA the provider expects.
	UserAgent string `yaml:"user_agent,omitempty"`
}

// NodeConfig describes this bypass node's role in the office network: the
// segment whose traffic the firewall diverts to us, the interface that
// diversion arrives on, and how we hand unproxied traffic back.
//
// Bypass deployment differs from upstream's sidecar role in one essential
// way: upstream's node was the network's egress, so "DIRECT" meant "leave
// through our own NIC". Here we are a detour beside the firewall, so
// DIRECT means "hand the packet back to the firewall" — and that requires
// a default route pointing at the firewall rather than at the internet.
// See ReturnConfig.
type NodeConfig struct {
	// ClientSubnet is the CIDR of the office segment whose traffic the
	// firewall's PBR diverts to us (e.g. "10.1.0.0/16"). Must match the
	// source-address in the firewall's policy-based-route rule.
	ClientSubnet string `yaml:"client_subnet"`

	// IngressIP is the address on IngressIface that mihomo's DNS server
	// binds to (see data_plane.dns.listen), and the address the firewall's
	// PBR rule points at as next-hop. Typically a /30 or /29 alongside the
	// firewall.
	//
	// Renamed from upstream's Tun0GatewayIP: there is no tun0 here.
	IngressIP string `yaml:"ingress_ip"`

	// IngressIface is the NIC that carries diverted traffic from the
	// firewall. Replaces upstream's tun0.
	IngressIface string `yaml:"ingress_iface"`

	// EgressIface is the NIC used to reach airport nodes on the public
	// internet. mihomo binds its proxy outbounds here so proxied traffic
	// does NOT follow the default route into the firewall (which would
	// bounce it back to us).
	EgressIface string `yaml:"egress_iface"`

	// Return describes how unproxied traffic gets back to the firewall.
	Return ReturnConfig `yaml:"return"`
}

// ReturnConfig pins the return path for traffic that the classifier sends
// DIRECT. Under the chosen design (see PLAN.md P2, "方案 B") this is the
// whole mechanism: mihomo re-originates a DIRECT flow from this host, and
// the default route sends it to the firewall's address rather than to the
// internet. install.sh installs exactly that route.
//
// Why this does not loop: the return flow originates from this host, so its
// source address is not in ClientSubnet and the firewall's PBR rule (which
// matches on source-address AND original ingress interface) does not
// re-capture it.
type ReturnConfig struct {
	// GatewayIP is the firewall's address on the ingress segment. install.sh
	// runs `ip route replace default via <GatewayIP>` so all non-proxied
	// egress lands on the firewall.
	GatewayIP string `yaml:"gateway_ip"`

	// Iface optionally pins the return device. Empty = let the kernel pick
	// from the route. Under the chosen design this can stay empty because
	// return traffic never shares an ingress decision with the firewall's
	// PBR rule; set it only if the host has multiple paths to GatewayIP and
	// you need to force one.
	Iface string `yaml:"iface,omitempty"`
}

// A note on the bool fields in this block: yaml.v3 decodes an absent key as
// the zero value, so a plain `bool` cannot express "default true" — omitting
// the line silently means false. Every field whose safe default is ON is
// therefore a *bool, where nil means "use the default". Fields whose default
// is OFF (AutoFailover, EgressProbe) stay plain bools, because there the zero
// value is already correct.
//
// This matters more here than elsewhere: a hand-written config that forgets
// `checks.engine_alive` would report healthy forever, which is precisely the
// failure this component exists to prevent.
type WatchdogConfig struct {
	// Enabled gates the whole subsystem. nil/true = on (and then
	// LivenessIP decides whether it can actually run); false = off.
	Enabled *bool `yaml:"enabled"`

	// Interval is the self-check period. Too short flaps; too long widens
	// the black-hole window. Default 10s.
	Interval time.Duration `yaml:"interval"`

	// FailThreshold is how many consecutive failing rounds mark the node
	// unhealthy. Guards against acting on a single transient error.
	// Default 3.
	FailThreshold int `yaml:"fail_threshold"`

	// RecoverThreshold is how many consecutive passing rounds mark it
	// healthy again. Mirrors the firewall's own revertive semantics, which
	// also require N consecutive responses before declaring Up. Default 3.
	RecoverThreshold int `yaml:"recover_threshold"`

	// Checks selects and parameterizes the individual self-checks.
	Checks WatchdogChecks `yaml:"checks"`

	// LivenessIP is the address the firewall's IP-Link probe targets.
	//
	// REQUIRED at deploy time — there is deliberately no default. It is the
	// only health signal path between this host and the firewall, and every
	// way of getting it wrong fails silently:
	//   - left empty        → nothing is withdrawn, the firewall never learns
	//   - set to IngressIP  → withdrawing it also drops SSH and the API,
	//                         removing your ability to log in and diagnose
	//   - set to an address another host already uses → an address conflict
	// so install.sh's precheck rejects an empty value and one equal to
	// IngressIP. Pick a spare address in the ingress segment and bind it to
	// lo (the default for LivenessIface).
	LivenessIP string `yaml:"liveness_ip"`

	// LivenessIface is the device LivenessIP is bound to. Default "lo".
	// Set it to the physical ingress NIC when the firewall probes with
	// `mode arp` — ARP does not cross layer 3, so a loopback-bound address
	// is unreachable to an ARP probe.
	LivenessIface string `yaml:"liveness_iface"`

	// AutoFailover decides whether an unhealthy verdict is merely reported
	// or acted on:
	//
	//	false (default) — alert only; LivenessIP stays up and the firewall
	//	                  keeps diverting. You cut over manually.
	//	true            — withdraw LivenessIP, so the firewall's IP-Link
	//	                  goes Down and traffic returns to direct routing
	//	                  on its own.
	//
	// Default false on purpose. During the trial period there are few users
	// and a manual cutover is enough, while an automatic withdrawal during a
	// half-dead state (probe says healthy, forwarding is black-holing) gives
	// false confidence. Flip to true once the failure modes have been
	// observed for a week or two — it is a config change, not a code change.
	AutoFailover bool `yaml:"auto_failover"`

	// NotifyOnStateChange sends a Lark message on each health transition,
	// naming the check that failed. nil/true = on.
	NotifyOnStateChange *bool `yaml:"notify_on_state_change"`
}

// IsEnabled reports whether the watchdog should run.
func (w WatchdogConfig) IsEnabled() bool { return w.Enabled == nil || *w.Enabled }

// ShouldNotify reports whether health transitions should be pushed.
func (w WatchdogConfig) ShouldNotify() bool {
	return w.NotifyOnStateChange == nil || *w.NotifyOnStateChange
}

// WatchdogChecks selects the individual self-checks. All enabled checks must
// pass for the node to be considered healthy. As with WatchdogConfig, every
// check that defaults ON is a *bool so that omitting it does not disable it.
type WatchdogChecks struct {
	// EngineAlive verifies the mihomo process is up and its clash-api
	// answers /version. nil/true = on.
	EngineAlive *bool `yaml:"engine_alive"`

	// DataplaneRules verifies the TPROXY rules are in place.
	//
	// This does NOT re-implement the check: it reads the snapshot of
	// internal/dataplane/assert.go, which already asserts these every 30s
	// and performs targeted self-repair (see its package doc for the
	// 2026-08-12 outage that motivated it). Re-implementing it here would
	// put repair and withdrawal in a fight — rules get flushed, watchdog
	// withdraws, firewall cuts over, assert repairs, address returns,
	// firewall cuts back — so the split is: assert repairs, watchdog
	// reports. nil/true = on.
	DataplaneRules *bool `yaml:"dataplane_rules"`

	// PoolHealthyMin is how many egress nodes must be currently healthy for
	// this check to pass (read from NodeScorer's state). nil = default 1:
	// with none healthy, every proxied flow is dead even though the host and
	// its rules are fine. An explicit 0 disables the check.
	PoolHealthyMin *int `yaml:"pool_healthy_min"`

	// EgressProbe enables an end-to-end check: fetch EgressProbeURL through
	// the proxy. This is the only check that proves the entire chain works,
	// but it generates real traffic on every round. Default false.
	EgressProbe bool `yaml:"egress_probe"`

	// EgressProbeURL is the URL fetched by EgressProbe. Default
	// http://cp.cloudflare.com/generate_204 — small, no TLS handshake, and
	// purpose-built for connectivity checks.
	EgressProbeURL string `yaml:"egress_probe_url"`

	// EgressProbeTimeout caps each end-to-end probe. Default 5s.
	EgressProbeTimeout time.Duration `yaml:"egress_probe_timeout"`
}

// CheckEngineAlive reports whether the engine check is enabled (default true).
func (c WatchdogChecks) CheckEngineAlive() bool { return c.EngineAlive == nil || *c.EngineAlive }

// CheckDataplaneRules reports whether the rule check is enabled (default true).
func (c WatchdogChecks) CheckDataplaneRules() bool {
	return c.DataplaneRules == nil || *c.DataplaneRules
}

// EffectivePoolHealthyMin returns the pool health floor, defaulting to 1.
// An explicit 0 disables the check.
func (c WatchdogChecks) EffectivePoolHealthyMin() int {
	if c.PoolHealthyMin == nil {
		return 1
	}
	return *c.PoolHealthyMin
}

// DataPlaneConfig describes the proxy data plane (mihomo) the control plane
// renders to + reloads. mihomo is the only supported engine; the field name
// `data_plane` is engine-neutral by intent (so a future swap doesn't force
// another rename).
type DataPlaneConfig struct {
	// ConfigPath is where the renderer writes mihomo's config.yaml.
	// Defaults to /var/lib/turnout/mihomo/config.yaml.
	ConfigPath string `yaml:"config_path"`

	LogLevel string `yaml:"log_level"`

	// RuleSetsDir holds .mrs files used by mihomo. Pre-fetched into the
	// install tarball by scripts/stage.sh; expanded at startup.
	// Defaults to /var/lib/turnout/mihomo/rule-sets.
	RuleSetsDir string `yaml:"rule_sets_dir"`

	ClashAPI ClashAPIConfig `yaml:"clash_api"`

	// TUN drives mihomo's TUN inbound that catches forwarded traffic via
	// fwmark policy routing.
	TUN TUNConfig `yaml:"tun"`

	// DNS drives mihomo's DNS server upstreams.
	DNS DNSConfig `yaml:"dns"`

	// Route drives the rule-set URLs + whitelist mode.
	Route RouteConfig `yaml:"route"`

	// URLTest tunes mihomo's load-balance internal url-test. Note: this
	// is mihomo's own concept, not our NodeScorer — they're complementary.
	URLTest URLTestConfig `yaml:"url_test"`

	// TProxyPort is the port mihomo listens on for transparent-proxy
	// (TPROXY) inbound traffic. When non-zero, iproute.sh redirects
	// non-DNS TCP/UDP from the diverted office subnet to this port using
	// the kernel's TPROXY target, which preserves the original client
	// source IP in mihomo's connection metadata.
	//
	// This is the ONLY mechanism that preserves real source IPs. TUN mode
	// (system OR gvisor) always reports 198.18.0.0 for all clients because
	// the network stack reconstructs TCP connections without propagating the
	// original IP header — confirmed on production node 89, 2026-06-06.
	//
	// per_terminal routing (load_balance.per_terminal) REQUIRES this field
	// to be set. Validation refuses tproxy_port=0 — TUN-only mode collapses
	// all clients to 198.18.0.0 and is no longer a supported deploy path.
	TProxyPort int `yaml:"tproxy_port"`

	// Legacy ad-hoc inbounds, retained for cmd/selftest. Empty = omitted.
	SOCKSListen string `yaml:"socks_listen"`
	HTTPListen  string `yaml:"http_listen"`
}

type ClashAPIConfig struct {
	ExternalController string `yaml:"external_controller"`
	Secret             string `yaml:"secret"`
}

type TUNConfig struct {
	Enabled       bool   `yaml:"enabled"`
	InterfaceName string `yaml:"interface_name"`
	Address       string `yaml:"address"` // e.g. "172.19.0.1/30"
	FWMark        int    `yaml:"fwmark"`
	RoutingTable  int    `yaml:"routing_table"`
	// Stack selects mihomo's TUN network stack:
	//   "system" (default) — kernel handles the TUN socket.
	//   "gvisor"           — userspace stack.
	//
	// IMPORTANT: neither stack preserves the real client sourceIP in mihomo's
	// connection metadata. Both collapse sourceIP to 198.18.0.0 (the TUN device
	// address) because the kernel/gvisor stack reconstructs the TCP connection
	// from raw TUN packets without propagating the original IP header.
	// Per-terminal routing requires TPROXY (data_plane.tproxy_port), not gvisor.
	Stack string `yaml:"stack"`
}

// LoadBalanceConfig tunes how overseas (default-pool-bound) traffic is spread.
type LoadBalanceConfig struct {
	// PerTerminal, when true, pins each client terminal's whitelisted
	// (domain-matched) traffic to a single egress node — "one terminal,
	// one egress". Eliminates the multi-node drift within one logical
	// session (chatgpt.com / chat.openai.com / ws.chatgpt.com all exit the
	// same IP) that trips OpenAI/Cloudflare anomaly detection.
	//
	// REQUIRES data_plane.tproxy_port to be set. TPROXY preserves the real
	// client sourceIP so SRC-IP-CIDR slicing works. TUN mode
	// (tproxy_port=0) always collapses all clients to 198.18.0.0 regardless
	// of TUN stack (confirmed on production node 89, 2026-06-06).
	//
	// Mechanism: the renderer slices node.client_subnet into per-/32
	// SRC-IP-CIDR rules under a `perterm` sub-rule, assigning each terminal
	// to a qualified default-pool node via rendezvous (HRW) hashing. Whitelist
	// rules route to the perterm sub-rule instead of directly to `out`.
	PerTerminal bool `yaml:"per_terminal"`
}

type DNSConfig struct {
	// Listen overrides the default <Tun0GatewayIP>:53. Useful in lab.
	Listen string `yaml:"listen"`
	// CNDoH is the upstream pool for CN-side resolution.
	CNDoH []string `yaml:"cn_doh"`
	// ProxyDoH is the upstream pool for non-CN resolution. Routed through
	// mihomo's "out" selector → default-pool by the renderer.
	ProxyDoH []string `yaml:"proxy_doh"`
	// BootstrapResolver is an IP literal used to resolve any DoH/DoT host
	// names without chicken-and-egg (e.g. "udp://119.29.29.29").
	BootstrapResolver string `yaml:"bootstrap_resolver"`
	// NodeResolver lists the upstreams used to resolve the airport-node
	// server hostnames matched by NodeResolverSuffixes. Default
	// ["udp://119.29.29.29"]. Only takes effect together with
	// NodeResolverSuffixes — on its own it does nothing.
	//
	// Why a plain-UDP upstream is worth having at all: mihomo's
	// proxy-server-nameserver ("psn") is a separate resolver instance from
	// `nameserver`, and a DoH frontend that answers NXDOMAIN for a name
	// that really exists produces "dns resolve failed: couldn't find ip" at
	// dial time. Measured on node 92 (2026-08-12) against the ash
	// provider's ingress z7mp4a9xq2k8f3r-r9.edg3.org: doh.pub's DoH
	// frontend returned NXDOMAIN 0/3 while plain UDP to 119.29.29.29 (same
	// operator, DNSPod) resolved 5/5. The two frontends do not share
	// recursion state.
	//
	// ⚠️ Appending an upstream to the psn LIST does not reliably fix that,
	// and the original 2026-08-12 fix which did so was wrong about the
	// mechanism. mihomo fires ALL psn upstreams in PARALLEL via `picker`
	// and takes the first non-error answer; NXDOMAIN is NOT an error there
	// (only SERVFAIL/REFUSED convert), so a fast NXDOMAIN WINS the race and
	// defeats a healthy upstream in the same list. Verified directly: psn =
	// [always-NXDOMAIN, udp://119.29.29.29] produced 10 resolve failures in
	// 10 attempts. List order is cosmetic.
	//
	// It also had a side effect: 119.29.29.29 answers in 0.04-0.06s versus
	// doh.pub's 0.164-0.291s, so in a latency race the plain-UDP upstream
	// silently became the de facto PRIMARY resolver for every node
	// hostname, moving all of them onto a spoofable transport.
	//
	// Hence the suffix-scoped design: psn itself stays CNDoH-only, and
	// NodeResolverSuffixes pins just the affected provider domains to these
	// upstreams via proxy-server-nameserver-policy, which is a deterministic
	// map lookup rather than a race. Everything else keeps resolving over
	// DoH.
	NodeResolver []string `yaml:"node_resolver,omitempty"`
	// NodeResolverSuffixes lists the domain suffixes pinned to NodeResolver
	// through mihomo's proxy-server-nameserver-policy. Empty (the default)
	// means no policy is emitted and psn is CNDoH-only.
	//
	// Populate this only for provider ingress domains with a demonstrated
	// DoH-NXDOMAIN problem, and keep it as narrow as possible: every suffix
	// listed here is resolved over plain UDP, i.e. spoofable. Node-hostname
	// resolution is a dial-time internal lookup where availability
	// dominates integrity, but that tradeoff should be made per-domain, not
	// globally.
	//
	// Accepts "edg3.org", ".edg3.org", or "+.edg3.org" — all normalize to
	// mihomo's "+.edg3.org" wildcard key form.
	//
	// Supported since mihomo v1.19.26 (config/config.go:240); verified with
	// `mihomo -t` on the node before rollout.
	NodeResolverSuffixes []string `yaml:"node_resolver_suffixes,omitempty"`
	// PreloadDomains is the list of overseas domains turnout-gateway will
	// keep warm in mihomo's DNS cache.
	//
	// Two things clear that cache: TTL expiry, and every PUT /configs
	// (mihomo rebuilds its resolver in ApplyConfig → updateDNS). The second
	// is why the preloader also runs a sweep right after each hot reload —
	// without it, pool churn can leave the cache cold for the whole
	// preload_interval, and the first lookup of each domain costs
	// 0.24-1.2s (measured 2026-10-23) instead of ~0ms.
	//
	// Curate this from what the office actually opens first (the whitelist's
	// high-traffic destinations); each sweep is one A query per domain.
	// Empty disables the preloader entirely.
	PreloadDomains []string `yaml:"preload_domains,omitempty"`
	// PreloadInterval is how often each preloaded domain is re-queried.
	// Default 5m. 0 disables preload (regardless of PreloadDomains).
	PreloadInterval time.Duration `yaml:"preload_interval,omitempty"`
	// FakeIPSkipSuffixes lists intranet/private domain suffixes that must
	// resolve via CN DoH (they land in nameserver-policy → CNDoH). Needed
	// for services whose hostnames aren't on geosite-cn but resolve to
	// CN/LAN IPs reached DIRECTly — the default nameserver is proxyDoH
	// (overseas), which has no records for them. Name kept for yaml/API
	// back-compat; predates the 2026-07-06 redir-host switch.
	FakeIPSkipSuffixes []string `yaml:"fake_ip_skip_suffixes,omitempty"`

	// Hijack controls transparent capture of DNS that the firewall diverts
	// here. Default true (nil → true).
	//
	// Terminals keep their own resolvers (223.5.5.5, 119.29.29.29, the
	// ISP's): we may not change them. Once the firewall's PBR diverts that
	// UDP/TCP 53 traffic to this box, something must answer it — the
	// TPROXY chain deliberately skips dport 53, so without hijack the query
	// is forwarded back out the default route, re-diverted by the firewall,
	// and loops until TTL expires. Observed 2026-10-22: every diverted
	// terminal lost DNS entirely.
	//
	// With hijack on, iproute.sh DNATs non-local dport-53 traffic from
	// client_subnet to <ingress_ip>:53 (mihomo's DNS). conntrack rewrites
	// the reply's source back to the resolver the client asked, so the
	// terminal sees 119.29.29.29 answer — same model as OpenClash /
	// ShellCrash "DNS hijack", sing-box hijack-dns, mihomo tun dns-hijack.
	//
	// Encrypted DNS (DoT 853, DoH 443) is not captured: DoH is ordinary
	// HTTPS and DoT would need TLS termination. Those terminals fall back
	// to SNI sniffing, which still routes correctly.
	Hijack *bool `yaml:"hijack,omitempty"`
}

// HijackEnabled reports whether diverted DNS is captured (default true).
func (d DNSConfig) HijackEnabled() bool { return d.Hijack == nil || *d.Hijack }

type RouteConfig struct {
	GeositeURL string `yaml:"geosite_url"`
	GeoIPURL   string `yaml:"geoip_url"`

	// Mode controls how non-CN traffic is split.
	//   "overseas" (default): every non-CN destination → default-pool. CN
	//                         domains/IPs still go DIRECT via geosite-cn /
	//                         geoip-cn. Most transparent to clients.
	//   "whitelist":          only domains hitting Whitelist.* go to
	//                         default-pool (or its named pool); everything else
	//                         goes DIRECT. Saves airport bandwidth at the
	//                         cost of curating the list.
	Mode string `yaml:"mode"`

	// Whitelist is consulted only when Mode == "whitelist".
	Whitelist WhitelistConfig `yaml:"whitelist"`

	// AdBlock rejects connections to three domain lists, each rendered as
	// `RULE-SET,<tag>,REJECT` ahead of geosite-cn (mihomo matches top-down, so
	// a rule after the CN-direct line would never see CN-hosted ad domains):
	//
	//	category-ads-all  MetaCubeX's superset (903). It is the BROADER list,
	//	                  not the narrower category-ads (843): the 60 extra
	//	                  entries are where the mainstream ad exchanges live
	//	                  (adnxs, casalemedia, openx, pubmatic, taboola). The
	//	                  same 60 also carry tracker/dev domains
	//	                  (+.sentry.io, +.segment.io, +.clearbit.com).
	//	anti-ad           anti-AD, CN-oriented plain text (~112k domains).
	//	cname-ads         AdGuard cname-trackers' disguised domains (~11.7k):
	//	                  first-party-looking names that CNAME to ad servers.
	//	                  A domain-level REJECT reaches those only via this list.
	//
	// There is deliberately no per-domain exclusion list — the operator's only
	// rollback is this switch (flip it off, re-render, no restart needed). The
	// accepted cost is the ad-list tail that shares a name with real content,
	// e.g. img1.126.net (163's image CDN) is on anti-AD.
	//
	// Default false. Turning it on changes behaviour for EVERY terminal on
	// the diverted segment. Every file must be on disk (scripts/stage.sh ships
	// them) — the API handler refuses to enable the switch when any is
	// missing rather than silently blocking nothing.
	AdBlock bool `yaml:"ad_block"`
}

// WhitelistConfig enumerates what's allowed through the airport in
// whitelist mode. See docs/api.md for full semantics.
type WhitelistConfig struct {
	Geosites     StringList `yaml:"geosites"`
	Geoips       StringList `yaml:"geoips"`
	DomainSuffix []string   `yaml:"domain_suffix"`
	IPCIDR       []string   `yaml:"ip_cidr"`
	// FakeIPSkip is surfaced via PUT /api/whitelist as `fake_ip_skip`.
	// On mutation it is synced to cfg.DataPlane.DNS.FakeIPSkipSuffixes
	// so the renderer picks it up without a separate API call.
	FakeIPSkip []string `yaml:"fake_ip_skip"`
}

// StringList is yaml-decoded as []string but tolerates the legacy "list of
// {name, url}" mapping form so old gateway.yaml files keep loading.
type StringList []string

func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.SequenceNode {
		return fmt.Errorf("expected list, got kind %d", node.Kind)
	}
	out := make([]string, 0, len(node.Content))
	for _, item := range node.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			out = append(out, item.Value)
		case yaml.MappingNode:
			var m struct {
				Name string `yaml:"name"`
			}
			if err := item.Decode(&m); err != nil {
				return err
			}
			if m.Name != "" {
				out = append(out, m.Name)
			}
		default:
			return fmt.Errorf("unsupported yaml kind %d in StringList", item.Kind)
		}
	}
	*s = out
	return nil
}

// URLTestConfig drives mihomo's load-balance internal probe + url-test.
// Distinct from NodeQualifyConfig (which is turnout-gateway's own scorer);
// these thresholds shape mihomo's per-flow health-check + url-test cycle.
type URLTestConfig struct {
	// Interval: legacy field, kept for backward compatibility. Used as
	// fallback when HealthCheckInterval is unset. New configs should set
	// HealthCheckInterval directly. Default 3m.
	Interval time.Duration `yaml:"interval"`
	// HealthCheckInterval: how often mihomo internally probes each
	// LoadBalance member to update its alive bit. This is the FAST/binary
	// liveness signal — when a node TCP/HTTP-fails one probe, mihomo's
	// own LoadBalance routing skips it for new connections WITHOUT any
	// yaml rerender. Default 30s. Tune lower for snappier failover at
	// the cost of a small uptick in airport probe traffic; tune higher
	// only if airport quotas become a concern.
	//
	// Architectural rule: this MUST be ≤ NodeQualify.ScoringInterval.
	// Liveness is mihomo's job (this knob); graded eviction is the
	// scorer's job (slower cycle). If you raise this above the scorer's
	// interval, mihomo and the scorer trade roles and reloads churn.
	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	// Tolerance = ms hysteresis: only switch if a new candidate is faster
	// by this much (default 50). Mostly cosmetic under load-balance.
	Tolerance int `yaml:"tolerance"`
	// ProbeURL = URL probed for latency. Default gstatic.com/generate_204
	// because it must traverse GFW (which is what we want to verify).
	ProbeURL string `yaml:"probe_url"`
	// NodePattern is a Go-regexp; only outbounds whose tag matches are
	// added to default-pool. Empty = every airport node is a candidate.
	NodePattern string `yaml:"node_pattern"`
}

// NodeQualifyConfig is the threshold set for the NodeScorer. All thresholds
// must be satisfied simultaneously for a node to be considered "qualified"
// for the base default-pool. Probe results gate membership in named pools.
type NodeQualifyConfig struct {
	// Enabled turns the scorer on. Default true under mihomo.
	Enabled bool `yaml:"enabled"`
	// ScoringInterval is how often the scorer reads /proxies and
	// /connections and re-evaluates every node. Default 5m.
	//
	// Architectural rule: this is the SLOW/graded decision cycle —
	// long-term RTT degradation, CF challenge gating, persistent
	// suitability for named pools. Fast/binary liveness is mihomo's
	// LoadBalance health-check (data_plane.url_test.health_check_interval,
	// default 30s). Keep this ≥ ~10× the health-check interval so a
	// transient flap mihomo's already filtering doesn't cascade into
	// an unnecessary scorer-driven hot-reload.
	ScoringInterval time.Duration `yaml:"scoring_interval"`
	// TrialDuration is how long a newly measured node stays out of the
	// legacy K-gated routing pool (promotion) after its first successful
	// measurement. Default 24h. A deliberate region/pattern migration
	// needs a shorter value (e.g. 15m): with the 24h default the new
	// region cannot enter the routing pool for a day even though mihomo
	// already probes it. Only the legacy K-gated path reads this;
	// sizing_mode=eligibility uses its admission gate instead.
	TrialDuration time.Duration `yaml:"trial_duration"`
	// MaxRTTP50Ms: p50 RTT ceiling in ms. Default 500.
	MaxRTTP50Ms int `yaml:"max_rtt_p50_ms"`
	// MaxRTTP95Ms: p95 RTT ceiling in ms. Default 800.
	MaxRTTP95Ms int `yaml:"max_rtt_p95_ms"`
	// MaxJitterMs: p95-p50 spread in ms. Default 300.
	MaxJitterMs int `yaml:"max_jitter_ms"`
	// MaxFailRate: fraction of probes (delay=0 = failed) tolerated.
	// Default 0.25.
	MaxFailRate float64 `yaml:"max_fail_rate"`
	// MinProbes: minimum history entries before a node is eligible.
	// Default 2.
	MinProbes int `yaml:"min_probes"`
	// EvictStrikes: NOT HONOURED — no code path gates eviction on it.
	//
	// It was meant to be "consecutive failing rounds before a node leaves
	// the pool", i.e. a 2-round (10min at ScoringInterval=5m) grace period
	// against transient noise. Neither path implements that:
	//
	//   - sizing_mode=eligibility (what 92 runs): nodeState.strikes is
	//     incremented and reset but never compared — see scorer.go's
	//     eligibilityPoolLocked, "Diagnostic counters only; eligibility
	//     does not gate on them". A member leaves after ONE round with
	//     Qualified=false.
	//   - sizing_mode=legacy: scorer.go's ranking pass says it outright —
	//     "Not in top-K (or not qualified): exit immediately. No
	//     EvictStrikes hysteresis — ranking is the sole criterion."
	//
	// Verified 2026-09-10 by experiment, not by reading: setting this to 1
	// leaves TestDecision_CatastrophicMemberEvictedWhenSpareReady and
	// TestDecision_HysteresisHoldsWithoutSpare both passing. The grace
	// period the latter observes comes from the MinPoolSize/kTarget
	// under-capacity refill, not from strikes.
	//
	// The only live read is the startup log line in scorer.go's Start.
	// Kept (with its default) so existing gateway.yaml files do not fail
	// to parse; do not rely on it. Giving eligibility a real exit-side
	// hysteresis would mean adding the missing comparison here, which is
	// a behaviour change and needs its own review.
	EvictStrikes int `yaml:"evict_strikes"`
	// ReadmitStrikes: consecutive passing rounds before a non-member node
	// is added back. Default 1 (no hysteresis). Read by BOTH the legacy
	// K-gated path and, since 2026-09-09, the sizing_mode=eligibility
	// admission gate.
	//
	// Set this to 2-3 under eligibility mode. The earlier reasoning here —
	// "one passing round already represents 10 mihomo health-check cycles,
	// so it is enough to trust readmission" — is wrong, and 92 flapped for
	// it: mihomo keeps at most 10 url-test entries at a 30s interval, so
	// those 10 cycles are ONE fresh ~independent sample per 5-minute round,
	// not 10 confirmations. A node with sustained ~30-40% loss clears
	// fail_rate<=0.25 on a minority of rounds by sampling luck alone, so at
	// ReadmitStrikes=1 it is admitted, trips the liveness gate, exits, and
	// repeats — one hot-reload per crossing. N consecutive rounds is the
	// part that actually spans independent samples.
	ReadmitStrikes int `yaml:"readmit_strikes"`
	// DeadEvictRounds: consecutive scoring rounds a node must be
	// alive=false (mihomo cannot connect) before it is evicted from the
	// eligibility routing set, EVEN IF still Qualified via gstatic
	// recentOk>0. Closes the "soft-dead incumbent" gap: an alive=false
	// node that keeps passing gstatic (fail<0.9) is otherwise retained by
	// the incumbent exception indefinitely, stranding the ~13% of
	// terminals whose per-terminal HRW top-2 both land on such nodes
	// (mihomo fallback cannot rescue them — both targets dead).
	// Default 4 (~20min at 5m ScoringInterval): observed correlated Hutao
	// flaps self-heal in 1-2 rounds, so 4 evicts only SUSTAINED deadness,
	// never a recoverable blip (which would re-introduce the Plan-A
	// alive-bit churn). Eviction is floor-subordinate: dead nodes are
	// retained if evicting them would drop the routing set below
	// MinPoolSize (a dead node in HRW is still a fallback target; an
	// below-floor pool breaks the single-egress invariant). NOT persisted
	// as dwell state (resets to 0 on restart, like strikes). 0 disables.
	DeadEvictRounds int `yaml:"dead_evict_rounds"`
	// HotReloadMinInterval throttles how often pool changes can trigger
	// a clash-api PUT /configs?force=true. When a pool change is
	// detected within this window, the change is held off until the
	// next scoring round; the runtime mihomo state continues using the
	// last applied pool. 0 = no throttle (every change reloads
	// immediately, original behavior). Default 90s — long enough that
	// transient probe noise can't cascade reloads, short enough that a
	// real degradation propagates within ~2 scoring rounds.
	HotReloadMinInterval time.Duration `yaml:"hot_reload_min_interval"`

	// Probes defines per-target reachability checks (e.g. "can this node
	// load chatgpt.com without hitting Cloudflare's bot challenge?"). Each
	// probe runs from each candidate node periodically; results land in
	// NodeHealth.Probes and gate membership in named Pools.
	Probes []ProbeConfig `yaml:"probes"`

	// PoolSizing controls dynamic K (default-pool target size). When TActive=0
	// (default) the legacy "every qualified candidate is in pool" behavior
	// is preserved. When TActive>0 the scorer ranks qualified candidates
	// by composite score and gates the pool to top-K, sized from the
	// formula:
	//
	//   K = clamp(
	//     ⌈T_active × surge / cap_per_node⌉,
	//     K_min(T_active),
	//     min(K_max, |Tier1|),
	//   )
	//   where K_min(T) = max(2, ⌈T / (cap × 1.5)⌉ + 1)  // failure resilience
	//
	// ReadmitStrikes gates membership entry (EvictStrikes does not gate
	// exit — see its field doc);
	// HotReloadMinInterval throttles reload frequency. The result: a small
	// stable set of best-quality egresses for a given terminal load,
	// preserving per-terminal HRW identity (perterminal.go).
	//
	// Only consulted when PoolMode=auto.
	PoolSizing PoolSizingConfig `yaml:"pool_sizing"`

	// SwapThresholdScore is the absolute long-EWMA score margin a
	// non-pool candidate must beat the worst pool member by, in order
	// to be promoted. 0 = no margin (behave like before — top-K wins
	// regardless of how thin the gap is). Higher values = stickier pool
	// (resists "tied for top-K" flapping that would otherwise cause
	// frequent IP rotations).
	//
	// Tuning: compositeScore is roughly p95_ms scale (with jitter +
	// fail_rate contributions). 100 ≈ "100ms p95 better" — modest
	// but meaningful. 300 = "300ms p95 better OR fail_rate 0.30 lower"
	// = strong signal required.
	//
	// Default is 400 (applyDefaults), NOT 100 — this comment said 100
	// until 2026-08-12 while the code had said 400 since the anti-flap
	// work; 100 was measured to swap ~67×/24h.
	//
	// NB: this gate is an ABSOLUTE score margin, so it is calibrated to
	// whatever scale compositeScore happens to be on. Any change to the
	// score's dominant term rescales the gate's effective strictness
	// without touching this number — e.g. moving the latency term from an
	// unloaded rtt_p95 (~245ms observed) to a concurrent-load p95
	// (~1562ms observed) inflates inter-node gaps ~6× and thereby
	// weakens this gate ~6×. If you change compositeScore, re-derive
	// this value in the same change.
	SwapThresholdScore float64 `yaml:"swap_threshold_score"`

	// PoolMode selects who owns pool composition.
	//
	//	"auto"   — scorer K-gating (legacy; subject to detection signal from
	//	           5-min auto rotation, retained for backward compat)
	//	"manual" — operator-owned via PoolMembers; scorer is observation-only
	//	           and never auto-rotates the pool. Routing is fixed to the
	//	           PoolMembers list. Emergency events still fire signals
	//	           (Push notification) but a follow-up phase wires the
	//	           EmergencyPromoteChain auto-promotion behavior. (Default
	//	           in production going forward — eliminates the 5-min auto-IP
	//	           rotation that CF/OpenAI behavioral models would flag.)
	//
	// Default "auto" for backward compat with deployments that haven't
	// migrated. Operator should set "manual" + populate PoolMembers.
	PoolMode string `yaml:"pool_mode"`

	// SizingMode selects the pool-composition algorithm WITHIN auto mode.
	// Orthogonal to PoolMode: it only takes effect when PoolMode=auto and
	// is ignored under manual.
	//
	//	"legacy"      — K-gating: computeK forces a fixed target size and
	//	                the fill post-pass refills to it every round. This is
	//	                the source of the chronic ~50 swaps/day (a slower node
	//	                is forced into the marginal slot, then ping-pongs).
	//	"eligibility" — no fixed K. The routing set = every node that passes
	//	                the quality gate (with hysteresis); per-terminal HRW
	//	                draws from that variable-size set. K survives only as
	//	                a redundancy floor (min_pool_size) and a safety ceiling
	//	                (k_max). See docs/design-eligibility-set-selection.md.
	//
	// Default "legacy" so existing deployments are unchanged until the
	// operator opts in after shadow-mode validation. An unrecognized value
	// falls back to "legacy" with a warning (fail-closed) — a typo must not
	// silently run an unintended sizer.
	SizingMode string `yaml:"sizing_mode"`

	// SizingShadow, when true and SizingMode=legacy, runs the eligibility
	// selection IN PARALLEL each scoring round and logs how it WOULD differ
	// from the live legacy decision — without changing any actual pool
	// membership. This is the pre-cutover validation path: run it in
	// production for ≥24h, read the diff logs, and only then flip
	// sizing_mode to "eligibility". No effect when SizingMode=eligibility
	// (the eligibility path is already live) — the diff would be empty.
	SizingShadow bool `yaml:"sizing_shadow"`

	// PoolMembers is the operator-owned list of node tags that carry
	// production traffic when PoolMode=manual. Members must reference
	// node tags that exist in the active subscription set; missing tags
	// are dropped at render time with a warning. Order is irrelevant —
	// per-terminal HRW assigns terminals to members deterministically by
	// hash, not order.
	//
	// This is the "ground truth" for the routing pool. Treat the same way
	// as `subscriptions:` — operator-owned, do NOT auto-modify during
	// node-sync / schema-migration / yaml-splice operations.
	PoolMembers []string `yaml:"pool_members"`

	// EmergencyPromoteChain is the operator's pre-approved replacement
	// queue for when an active PoolMembers entry is auto-evicted by the
	// emergency path (node fail_rate=100% sustained 30min). System walks
	// this list in order, picking the first not-already-in-pool entry to
	// replace the evicted node so pool size stays at K.
	//
	// Pre-approval matters: ops cannot always be online. With this list
	// the system can keep the pool at full size during single-node
	// failures without waiting for human approval.
	//
	// Schema is in place from Step 0; the auto-promote behavior wires up
	// in Phase 2.
	EmergencyPromoteChain []string `yaml:"emergency_promote_chain"`
}

// PoolSizingConfig controls dynamic K computation. See NodeQualifyConfig.PoolSizing.
type PoolSizingConfig struct {
	// TActive is the operator-supplied 7-day distinct active terminal
	// count. Used to compute K (pool target size). Set this from your own
	// DHCP lease or accounting data; recompute weekly, ignore daily
	// fluctuations.
	// Default 50. Previously, TActive=0 triggered legacy "all qualified
	// nodes in pool" behavior — that mode is removed; K-gating is always on.
	TActive int `yaml:"t_active"`
	// CapPerNode is the per-egress sustained terminal capacity. Operator-
	// tuned per subscription tier; default 10 (conservative — fishcloud
	// direct, ash IEPL etc. typically tolerate ~10-15 concurrent terminals
	// before P95 climbs). Should be re-validated by stress.sh per node tier.
	CapPerNode int `yaml:"cap_per_node"`
	// Surge is the peak/avg ratio. Default 1.5 (evening peak ~1.5× the
	// daytime mean). Drives the K_demand calculation.
	Surge float64 `yaml:"surge"`
	// KMin is the absolute floor on K (independent of T). Default 3 — even
	// for tiny terminal counts, we want some redundancy so a single node
	// failure doesn't strand all flows.
	KMin int `yaml:"k_min"`
	// KMax is the detection-surface ceiling on K. Default 12 — empirically
	// CF/OpenAI cluster ≤ 12 stable IPs as "small enterprise NAT" (legitimate
	// identity); ≥ 20 trends toward "VPN infrastructure". Stable rotation
	// matters more than absolute count, but a low ceiling further reduces
	// the surface for IP cataloging.
	KMax int `yaml:"k_max"`
	// MinPoolSize is the hard lower bound on routing pool size. When the
	// pool would fall below this (due to evictions or insufficient qualified
	// nodes), the scorer fills with the best available nodes including
	// cold-start (trial) nodes. Default 3.
	MinPoolSize int `yaml:"min_pool_size"`
}

// ProbeConfig is one site-specific reachability check. Probes are NOT
// part of the basic RTT-qualification thresholds — a node failing probe
// X is removed only from pools that list X in `requires_passing`, not
// from the base default-pool.
type ProbeConfig struct {
	// Name is the probe identifier. Use the destination hostname so the
	// API surface is self-descriptive (e.g. "chatgpt.com", "claude.ai").
	// Pool config's `requires_passing` references probes by Name.
	Name string `yaml:"name"`
	// URL is the full HTTPS URL to GET. Caller's responsibility to use a
	// path that returns a stable response without auth.
	URL string `yaml:"url"`
	// Interval between probes per node. Default 5m. Lower values increase
	// detection speed at the cost of airport traffic + risk of being
	// flagged as bot probing.
	Interval time.Duration `yaml:"interval"`
	// Timeout caps each probe. Default 10s.
	Timeout time.Duration `yaml:"timeout"`
	// Check defines the pass criteria.
	Check ProbeCheckConfig `yaml:"check"`
}

// ProbeCheckConfig describes what counts as a probe pass. Initial rules
// are simple; if more become necessary they can be added as additional
// fields rather than replacing this with a generic rule list.
type ProbeCheckConfig struct {
	// MaxStatus is the inclusive upper bound for status_code = pass.
	// Default 399 (i.e. 1xx-3xx pass, 4xx/5xx fail).
	MaxStatus int `yaml:"max_status"`

	// NB: there is deliberately no reject_cf_challenge knob. A response
	// carrying `cf-mitigated: challenge` is ALWAYS a probe failure — see
	// checkResponse in internal/nodescorer/probe.go.
	//
	// The field existed until 2026-08-12 with yaml tag reject_cf_challenge
	// and doc "default false", but probe.go never read it: the header check
	// was unconditional from the start. Removed rather than wired up,
	// because wiring it as documented would have been a regression. A
	// challenge means the request never reached the origin, so for a probe
	// whose entire job is measuring egress-IP reputation, counting it as a
	// pass is exactly backwards — it would let a blocklisted node into
	// openai-pool. For targets that challenge every headless client
	// regardless of IP (chatgpt.com's root HTML), the fix is to not probe
	// that URL; see the probe notes in configs/gateway.example.yaml.
}

// PoolConfig describes a named select group rendered alongside the default
// default-pool. Legacy pools (only requires_passing/rule_sets) are a probe-gated
// subset of default-pool and route like before. A "class pool" additionally
// declares its own candidate set (node_pattern), sizing, and per-terminal
// behavior, so different traffic classes can exit through different regions
// without touching the global default-pool.
type PoolConfig struct {
	// Name is the pool tag emitted into mihomo's proxy-groups (e.g.
	// "openai-pool"). Must be unique across pools.
	Name string `yaml:"name"`
	// RequiresPassing names probes (from NodeQualify.Probes[].Name) that
	// every member must currently pass. Empty = no extra gating beyond
	// default-pool's basic RTT thresholds.
	RequiresPassing []string `yaml:"requires_passing"`
	// RuleSets names rule-providers (e.g. "geosite-openai", "geosite-
	// anthropic") that route through this pool instead of `out`. Each
	// must be present in cfg.DataPlane.Route.Whitelist.Geosites OR
	// auto-fetched.
	RuleSets []string `yaml:"rule_sets"`

	// NodePattern is a Go RE2 regexp selecting candidate nodes for this
	// pool from ALL subscription nodes. Empty = inherit the global
	// data_plane.url_test.node_pattern. Setting it makes the pool a class
	// pool: its members can come from a different region than default-pool.
	// NOTE: Go RE2 has no lookahead/lookbehind — use alternation instead.
	NodePattern string `yaml:"node_pattern"`
	// Size caps the pool's member count after ranking by long EWMA.
	// 0 = use the global K target; if that is also 0, all eligible nodes.
	Size int `yaml:"size"`
	// PerTerminal marks a class pool and controls its egress stability.
	// true = emit fb-<pool>-<ip> groups so each terminal gets a stable
	// egress for this class. false = one shared load-balance group.
	// nil = legacy pool (not a class pool).
	PerTerminal *bool `yaml:"per_terminal"`
	// DomainSuffix lists exact domains routed to this class. Emitted
	// before rule_sets and the global whitelist, so a specific domain can
	// override a broader geosite hit (e.g. Gemini inside geosite-google).
	DomainSuffix []string `yaml:"domain_suffix"`
	// RuleLists adds operator-supplied rule lists fetched verbatim from a
	// URL (e.g. a vendor's Gemini.list) to this pool's routing. Unlike
	// RuleSets — MetaCubeX geosite tags converted to .mrs — these files are
	// Clash "classical" text: one full rule per line, so DOMAIN-KEYWORD
	// survives. scripts/stage.sh fetches each into
	// <rule_sets_dir>/<tag>.list; the renderer declares it as a classical
	// text rule-provider.
	RuleLists []RuleListConfig `yaml:"rule_lists"`
}

// RuleListConfig is one external classical rule list claimed by a pool.
type RuleListConfig struct {
	// Tag is the rule-provider name and the RULE-SET argument. It is also
	// the on-disk filename stem (<tag>.list), so it must be a safe path
	// component: [A-Za-z0-9][A-Za-z0-9._-]*. The json tags keep
	// GET /api/pools lowercase for the console.
	Tag string `yaml:"tag" json:"tag"`
	// URL is the upstream list. Only scripts/stage.sh reads it; the
	// renderer references the staged file by Tag alone.
	URL string `yaml:"url" json:"url"`
}

// IsClassPool reports whether the pool declares class semantics (own
// candidate set / sizing / per-terminal / exact domains). Legacy pools keep
// the old behavior: a probe-gated subset of default-pool with unified perterm.
func (p PoolConfig) IsClassPool() bool {
	return p.NodePattern != "" || p.Size > 0 || p.PerTerminal != nil || len(p.DomainSuffix) > 0
}

// PerTerminalEnabled reports the resolved per-terminal setting. nil (the
// legacy/default case) reads as false.
func (p PoolConfig) PerTerminalEnabled() bool {
	return p.PerTerminal != nil && *p.PerTerminal
}

// ruleListTagPattern keeps a rule-list tag filename-safe: it becomes
// <rule_sets_dir>/<tag>.list, so separators and traversal must be impossible.
var ruleListTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// validatePools enforces invariants the renderer and scorer rely on. Run at
// load time so a bad yaml never reaches a render or the live mihomo process.
func (c *Config) validatePools() error {
	seen := make(map[string]bool, len(c.Pools))
	// used maps every provider tag the renderer may already declare (rule-set
	// providers shared between the whitelist and pools, plus each pool's own
	// tags) to its owner. A rule_list reusing one of those tags would silently
	// replace its provider — a geosite .mrs and a classical text list are not
	// interchangeable — so that collision fails closed. Sharing a plain
	// rule_set between the whitelist and a pool stays legal: buildRuleProviders
	// emits it once and both rule lines point at it.
	used := make(map[string]string)
	for _, tag := range c.DataPlane.Route.Whitelist.Geosites {
		used[tag] = "data_plane.route.whitelist.geosites"
	}
	for _, tag := range c.DataPlane.Route.Whitelist.Geoips {
		used[tag] = "data_plane.route.whitelist.geoips"
	}
	for _, p := range c.Pools {
		for _, tag := range p.RuleSets {
			if _, ok := used[tag]; !ok {
				used[tag] = "pools[" + p.Name + "].rule_sets"
			}
		}
	}
	for i := range c.Pools {
		p := &c.Pools[i]
		if p.Name == "" {
			return fmt.Errorf("pools[%d]: name is required", i)
		}
		if seen[p.Name] {
			return fmt.Errorf("pools: duplicate pool name %q", p.Name)
		}
		seen[p.Name] = true
		if p.Size < 0 {
			return fmt.Errorf("pools[%s]: size must be >= 0", p.Name)
		}
		if p.NodePattern != "" {
			if _, err := regexp.Compile(p.NodePattern); err != nil {
				return fmt.Errorf("pools[%s]: invalid node_pattern: %w", p.Name, err)
			}
		}
		if p.PerTerminalEnabled() && c.Node.ClientSubnet == "" {
			return fmt.Errorf("pools[%s]: per_terminal requires node.client_subnet", p.Name)
		}
		for _, d := range p.DomainSuffix {
			if d == "" {
				return fmt.Errorf("pools[%s]: empty domain_suffix entry", p.Name)
			}
		}
		for _, rl := range p.RuleLists {
			owner := "pools[" + p.Name + "].rule_lists"
			switch {
			case rl.Tag == "":
				return fmt.Errorf("%s: tag is required", owner)
			case !ruleListTagPattern.MatchString(rl.Tag) || strings.Contains(rl.Tag, ".."):
				return fmt.Errorf("%s: invalid tag %q (want [A-Za-z0-9][A-Za-z0-9._-]*, no \"..\")", owner, rl.Tag)
			case strings.HasPrefix(rl.Tag, "geoip-"):
				// Behavior is inferred from this prefix elsewhere (rule
				// providers, DNS policy); a domain list must not look like
				// an IP set.
				return fmt.Errorf("%s: tag %q must not use the geoip- prefix", owner, rl.Tag)
			}
			if prev, ok := used[rl.Tag]; ok {
				return fmt.Errorf("%s: tag %q already claimed by %s", owner, rl.Tag, prev)
			}
			used[rl.Tag] = owner
			u, err := url.Parse(rl.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("%s: tag %q: url must be an absolute http(s) URL, got %q", owner, rl.Tag, rl.URL)
			}
		}
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	// KnownFields(true): an unknown key is an ERROR, not a silent no-op.
	//
	// This is not pedantry. `route:` and `dns:` live under data_plane, and a
	// hand-written yaml that puts them at the top level parses fine while
	// every value under them is discarded — mode silently falls back to
	// "overseas" and the deploy looks successful. That exact mistake shipped
	// in configs/gateway.example.yaml and cost an install to debug. Refusing
	// the file at load time is the only way the operator finds out.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validatePools(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.API.Listen == "" {
		// 18080 (not 8080) — inherited from upstream, where another agent
		// owned 127.0.0.1:8080. Any free port works; this one is kept so the
		// docs and deploy scripts stay consistent.
		c.API.Listen = "127.0.0.1:18080"
	}
	if c.Subscribe.HTTPTimeout == 0 {
		c.Subscribe.HTTPTimeout = 30 * time.Second
	}
	if c.Subscribe.UserAgent == "" {
		c.Subscribe.UserAgent = "ClashforWindows/0.20.39"
	}
	c.DataPlane.ApplyDefaults()
	c.NodeQualify.applyDefaults()
	c.Notifications.applyDefaults()
	c.Watchdog.applyDefaults()
}

// applyDefaults fills WatchdogConfig defaults.
//
// LivenessIP deliberately gets NO default — see its field doc. The bool
// fields are pointers so that "absent" and "explicitly false" stay
// distinguishable; nothing needs defaulting for them here, because the
// accessors (IsEnabled, ShouldNotify, CheckEngineAlive, ...) already read
// nil as "on".
func (w *WatchdogConfig) applyDefaults() {
	if w.Interval == 0 {
		w.Interval = 10 * time.Second
	}
	if w.FailThreshold == 0 {
		w.FailThreshold = 3
	}
	if w.RecoverThreshold == 0 {
		w.RecoverThreshold = 3
	}
	if w.LivenessIface == "" {
		w.LivenessIface = "lo"
	}
	if w.Checks.EgressProbeURL == "" {
		w.Checks.EgressProbeURL = "http://cp.cloudflare.com/generate_204"
	}
	if w.Checks.EgressProbeTimeout == 0 {
		w.Checks.EgressProbeTimeout = 5 * time.Second
	}
}

// applyDefaults fills NotificationsConfig defaults. Disabled by default —
// operator must explicitly enable. Defaults aim for "sane in production"
// when the operator opts in: signature on, dedup tight enough to suppress
// BGP flap spam, retries that don't drop urgent events on transient
// network errors.
func (n *NotificationsConfig) applyDefaults() {
	if n.LocalLogPath == "" {
		n.LocalLogPath = "/var/lib/turnout/notifications.log"
	}
	if n.DedupWindow == 0 {
		n.DedupWindow = 5 * time.Minute
	}
	if n.AggregationWindow == 0 {
		n.AggregationWindow = 30 * time.Second
	}
	if n.PerNodeRateLimitPerHour == 0 {
		n.PerNodeRateLimitPerHour = 4
	}
	if n.RetryAttempts == 0 {
		n.RetryAttempts = 3
	}
	if n.InstanceName == "" {
		// Identify the sending gateway in the Lark header. Hostname is the
		// natural per-node identity (e.g. "opsserver"); operator can
		// override with a friendlier label via yaml `instance_name`.
		if h, err := os.Hostname(); err == nil {
			n.InstanceName = h
		}
	}
	if n.Lark.SecretFile == "" {
		n.Lark.SecretFile = "/var/lib/turnout/lark-secret"
	}
	// Lark.SignatureRequired default true: any non-zero NotificationsConfig
	// loaded with Lark.WebhookURL set should require signing unless
	// operator explicitly turns it off (yaml `signature_required: false`).
	// Default Go zero value is false, so we only flip when WebhookURL
	// is set AND the operator hasn't explicitly written `false` — but
	// yaml.v3 can't distinguish missing-vs-explicit-false on a bool.
	// Safer: default ON only when URL is configured; if operator wants
	// OFF they leave URL empty (no webhook) or set up an unsigned bot
	// at their own risk. We log a WARN at startup if URL set + sig off.
	if n.Lark.WebhookURL != "" && !n.Lark.SignatureRequired {
		// not modifying the field — caller is responsible. Warning
		// emitted at scorer startup time (we don't have slog here).
	}
}

// ApplyDefaults fills in defaults for the DataPlane subtree. Public so
// callers that construct DataPlaneConfig directly (e.g. cmd/selftest) can
// invoke it.
func (c *DataPlaneConfig) ApplyDefaults() {
	if c.ConfigPath == "" {
		// mihomo workdir is /var/lib/turnout/mihomo; mihomo reads config.yaml
		// from there automatically (no -f flag). Must match the path in
		// deploy/node/turnout-mihomo.service (WorkingDirectory).
		c.ConfigPath = "/var/lib/turnout/mihomo/config.yaml"
	}
	if c.RuleSetsDir == "" {
		c.RuleSetsDir = "/var/lib/turnout/mihomo/rule-sets"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.ClashAPI.ExternalController == "" {
		c.ClashAPI.ExternalController = "127.0.0.1:9090"
	}

	// TUN defaults — only used when TUN.Enabled is true.
	if c.TUN.InterfaceName == "" {
		c.TUN.InterfaceName = "utun-turnout"
	}
	if c.TUN.Address == "" {
		c.TUN.Address = "172.19.0.1/30"
	}
	if c.TUN.FWMark == 0 {
		c.TUN.FWMark = 0x42
	}
	if c.TUN.RoutingTable == 0 {
		c.TUN.RoutingTable = 100
	}
	if c.TUN.Stack == "" {
		c.TUN.Stack = "system"
	}

	// DNS defaults.
	if len(c.DNS.CNDoH) == 0 {
		c.DNS.CNDoH = []string{
			"https://doh.pub/dns-query",
			"https://dns.alidns.com/dns-query",
		}
	}
	if len(c.DNS.ProxyDoH) == 0 {
		c.DNS.ProxyDoH = []string{
			"tls://1.1.1.1:853",
			"https://doh.pub/dns-query",
		}
	}
	if c.DNS.BootstrapResolver == "" {
		c.DNS.BootstrapResolver = "udp://119.29.29.29"
	}
	if len(c.DNS.NodeResolver) == 0 {
		c.DNS.NodeResolver = []string{"udp://119.29.29.29"}
	}
	if c.DNS.PreloadInterval == 0 && len(c.DNS.PreloadDomains) > 0 {
		c.DNS.PreloadInterval = 5 * time.Minute
	}

	// Route defaults — MetaCubeX/meta-rules-dat. mihomo loads .mrs from
	// the meta/ branch; the rulesets manager rewrites URLs at fetch time.
	if c.Route.GeositeURL == "" {
		c.Route.GeositeURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/cn.srs"
	}
	if c.Route.GeoIPURL == "" {
		c.Route.GeoIPURL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geoip/cn.srs"
	}
	if c.Route.Mode == "" {
		c.Route.Mode = "overseas"
	}

	// URLTest defaults.
	if c.URLTest.Interval == 0 {
		c.URLTest.Interval = 3 * time.Minute
	}
	if c.URLTest.HealthCheckInterval == 0 {
		// 30s: fast enough that LoadBalance routing skips a dead node within
		// one probe cycle; slow enough that 19 nodes × N subs × 30s probes
		// stay well under any airport's monthly quota.
		c.URLTest.HealthCheckInterval = 30 * time.Second
	}
	if c.URLTest.Tolerance == 0 {
		c.URLTest.Tolerance = 50
	}
	if c.URLTest.ProbeURL == "" {
		c.URLTest.ProbeURL = "https://www.gstatic.com/generate_204"
	}
}

// applyDefaults fills NodeQualify defaults. NodeQualify is enabled by
// default — the scorer is core to mihomo's pool management.
func (c *NodeQualifyConfig) applyDefaults() {
	// Enabled defaults true. Bool defaults can't distinguish "user set
	// false" from "field missing", so explicit false is the way to
	// disable; absent field = enabled.
	if c.ScoringInterval == 0 {
		c.ScoringInterval = 5 * time.Minute
		c.Enabled = true
	}
	if c.TrialDuration == 0 {
		c.TrialDuration = 24 * time.Hour
	}
	if c.MaxRTTP50Ms == 0 {
		c.MaxRTTP50Ms = 500
	}
	if c.MaxRTTP95Ms == 0 {
		c.MaxRTTP95Ms = 800
	}
	if c.MaxJitterMs == 0 {
		c.MaxJitterMs = 300
	}
	if c.MaxFailRate == 0 {
		c.MaxFailRate = 0.25
	}
	if c.MinProbes == 0 {
		c.MinProbes = 2
	}
	// Defaulted only so old configs parse; nothing reads the value to make
	// a decision. See the field doc.
	if c.EvictStrikes == 0 {
		c.EvictStrikes = 2
	}
	if c.DeadEvictRounds == 0 {
		c.DeadEvictRounds = 4
	}
	if c.ReadmitStrikes == 0 {
		c.ReadmitStrikes = 1
	}
	if c.HotReloadMinInterval == 0 {
		c.HotReloadMinInterval = 90 * time.Second
	}
	if c.SwapThresholdScore == 0 {
		// Strong stickiness gate: candidate must beat worst pool member
		// by ≥ 400 score-points before displacing it. At compositeScore
		// scale (p95_ms + 2×jitter + 5000×fail²), 400 ≈ "400ms p95
		// better, or fail_rate 0.28 lower" — a meaningful signal, not
		// noise. Raised from 100 to reduce pool churn: with 100 the pool
		// swapped ~67×/24h on a 22-node candidate set, causing IP drift
		// that trips CF/OpenAI behavioral models. Operator can lower to
		// 0 to revert to "any improvement triggers swap" semantics.
		c.SwapThresholdScore = 400
	}
	if c.PoolMode == "" {
		c.PoolMode = "auto"
	}
	switch c.SizingMode {
	case "":
		c.SizingMode = "legacy"
	case "legacy", "eligibility":
		// valid
	default:
		slog.Warn("nodescorer: unrecognized sizing_mode, falling back to legacy",
			"got", c.SizingMode)
		c.SizingMode = "legacy"
	}
	c.PoolSizing.applyDefaults()
	for i := range c.Probes {
		if c.Probes[i].Interval == 0 {
			c.Probes[i].Interval = 5 * time.Minute
		}
		if c.Probes[i].Timeout == 0 {
			c.Probes[i].Timeout = 10 * time.Second
		}
		if c.Probes[i].Check.MaxStatus == 0 {
			c.Probes[i].Check.MaxStatus = 399
		}
	}
}

// applyDefaults fills PoolSizingConfig defaults. K-gating is always on;
// TActive=0 in yaml gets the default of 50 (a reasonable starting point
// — operator should tune to their actual terminal count).
func (p *PoolSizingConfig) applyDefaults() {
	if p.TActive == 0 {
		p.TActive = 50
	}
	if p.CapPerNode == 0 {
		p.CapPerNode = 10
	}
	if p.Surge == 0 {
		p.Surge = 1.5
	}
	if p.KMin == 0 {
		p.KMin = 3
	}
	if p.KMax == 0 {
		p.KMax = 12
	}
	if p.MinPoolSize == 0 {
		p.MinPoolSize = 3
	}
}
