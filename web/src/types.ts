// Response shapes of the control-plane API. Source of truth is the Go
// handlers in internal/api/ and docs/api.md — every field the UI reads is
// optional unless the handler always sets it, because older nodes and
// scorer-less deployments omit whole blocks.

export interface HealthCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface Healthz {
  ok: boolean;
  scope?: string; // "process-liveness-only" when no asserter is configured
  detail?: string;
  asserted?: string;
  checks?: HealthCheck[];
}

export interface PoolSizing {
  k_target: number;
  k_current: number;
  t_active: number;
  tier1_count: number;
  supply_limited: boolean;
}

export interface PoolStability {
  window_hours: number;
  swap_count: number;
  rollback_count: number;
  unique_nodes_in: number;
  unique_nodes_out: number;
  oldest_at?: string;
}

export interface Capacity {
  sustained_max_users: number;
  degraded_max_users: number;
  measured_at?: string;
  measured_with?: string;
}

export interface Status {
  engine_ok: boolean;
  last_refresh?: string;
  node_count?: number;
  subscriptions?: number;
  pool_size?: number;
  pool_eligible?: number;
  pool_total?: number;
  pool_last_update?: string;
  sizing_mode?: string;
  pool_sizing?: PoolSizing;
  pool_stability_24h?: PoolStability;
  capacity?: Capacity;
}

export interface Egress {
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  org?: string;
  checked_at?: string;
}

export interface PoolMember {
  tag: string;
  delay_ms: number;
  last_check?: string;
  fail_rate: number; // -1 when the scorer is unavailable
}

export interface ActivePool {
  tag: string;
  pool_size: number;
  active: boolean;
  egress?: Egress;
  nodes?: PoolMember[];
}

/**
 * Read-only class-pool config from GET /api/pools (gateway.yaml `pools:`).
 * Live members are not here — they come from ActivePool.nodes, joined by
 * name. The default `default-pool` is not in this list; it is the ActivePool with
 * active=true and its pattern is `active_proxy.pool_filter`.
 */
export interface PoolConfig {
  name: string;
  /** Go RE2; empty means "inherit the global url_test.node_pattern". */
  node_pattern: string;
  /** 0 = use the global K target. */
  size: number;
  per_terminal: boolean;
  requires_passing?: string[];
  /** geosite-/geoip- tags this class claims. */
  rule_sets?: string[];
  /** Exact domains routed to this class. */
  domain_suffix?: string[];
}

export type Pools = PoolConfig[];

export interface Active {
  node?: {
    hostname?: string;
    kernel?: string;
    os?: string;
    uptime_seconds?: number;
    interfaces?: { name: string; ipv4?: string }[];
    client_subnet?: string;
    egress_iface?: string;
  };
  /**
   * Ingress describes the bypass role's link to the firewall — the things to
   * look at when the firewall reports this node down, or when diverted
   * traffic stops arriving. Mirrors nodeinfo.IngressInfo.
   */
  ingress?: {
    ingress_iface_up?: boolean;
    ingress_ip_present?: boolean;
    /** Current default route as a one-line string; empty when there is none. */
    return_route?: string;
    /** Whether the watchdog currently holds the address IP-Link probes. */
    liveness_up?: boolean;
  };
  turnout?: {
    gateway_version?: string;
    engine?: string;
    engine_version?: string;
    services?: Record<string, string>;
    subscriptions_count?: number;
    nodes_parsed?: number;
    last_refresh?: string;
  };
  active_proxy?: {
    reachable?: boolean;
    active_group?: string;
    pool_filter?: string;
    pool_mode?: string;
    last_swap_at?: string;
    pool_size?: number;
    pools?: ActivePool[];
  };
}

export interface ProbeResult {
  ok: boolean;
  status_code?: number;
  cf_mitigated?: boolean;
  latency_ms?: number;
  last_checked_at?: string;
  last_error?: string;
}

export interface Passive {
  active_conns: number;
  closed_window: number;
  failed_window: number;
  fail_rate: number;
  sample_window_sec: number;
}

export interface NodeHealth {
  name: string;
  sub?: string;
  alive: boolean;
  rtt_last_ms?: number;
  rtt_p50_ms?: number;
  rtt_p95_ms?: number;
  jitter_ms?: number;
  fail_rate?: number;
  probe_count?: number;
  throughput_bps?: number;
  qualified: boolean;
  in_pool: boolean;
  strikes?: number;
  ok_rounds?: number;
  reason?: string;
  probes?: Record<string, ProbeResult>;
  passive?: Passive;
}

export interface NodesHealth {
  qualified: number;
  total: number;
  last_pool_update?: string;
  last_scored_at?: string;
  thresholds?: {
    MaxRTTP50Ms?: number;
    MaxRTTP95Ms?: number;
    MaxJitterMs?: number;
    MaxFailRate?: number;
    Probes?: { Name: string; URL: string }[];
  };
  pool_mode?: string;
  nodes: NodeHealth[];
}

export interface UserInfo {
  upload: number;   // bytes used upstream
  download: number; // bytes used downstream
  total: number;    // quota ceiling in bytes (0 = unlimited)
  expire: number;   // unix seconds (0 = no expiry)
}

export interface Subscription {
  name: string;
  url: string; // masked: token=abcd***ef01 — never write this back
  enabled: boolean;
  format?: string;
  user_agent?: string;
  nodes_count?: number;
  last_refresh?: string;
  health?: string;       // "ok" | "fetch_error" | "parse_error" | "zero_nodes"
  health_err?: string;
  user_info?: UserInfo;
  // Client-gating pseudo-nodes the provider sent ("请改用 FlClash" etc).
  // Non-zero with health=zero_nodes means it refused our client entirely.
  gated_count?: number;
}

export interface RefreshInterval {
  seconds: number;
}

export interface Transition {
  at: string;
  type: string; // auto_swap | emergency_evict | emergency_swap | rollback
  added?: string[];
  removed?: string[];
  pool_before?: string[];
  pool_after?: string[];
  reason?: string;
  source?: string; // scorer | operator_api | operator_yaml
}

export interface Transitions {
  transitions: Transition[];
  quarantine?: Record<string, string>;
}

export interface TerminalNode {
  name: string;
  alive: boolean;
  health?: NodeHealth;
}

/**
 * Per-class egress for one terminal. Present for class pools configured with
 * per_terminal=true (e.g. ai-pool); the top-level primary/secondary on
 * TerminalAssignment describe the default "other" class.
 */
export interface TerminalPoolAssignment {
  pool: string;
  group_name?: string;
  primary?: TerminalNode;
  secondary?: TerminalNode;
  active_node?: '' | 'primary' | 'secondary';
  hint?: string;
}

export interface TerminalAssignment {
  ip: string;
  subnet: string;
  in_subnet: boolean;
  primary?: TerminalNode;
  secondary?: TerminalNode;
  active_node?: '' | 'primary' | 'secondary';
  group_name?: string;
  pool_mode: string;
  hint?: string;
  pools?: TerminalPoolAssignment[];
}

/* ── Watchdog (GET /api/watchdog/status) ─────────────────────────────────
 *
 * The bypass role's health reporter. Mirrors internal/watchdog.Status.
 *
 * Two states matter to the operator and they are NOT the same:
 *   state === 'unhealthy'   the data path is broken
 *   state === 'unknown'     no round has completed yet (startup)
 * 'unknown' must not be rendered as a fault — it resolves on its own within
 * one interval, and showing it red trains the operator to ignore the card.
 *
 * enabled === false means the watchdog is not running at all (config opted
 * out, or liveness_ip is unset). In that case the node cannot signal the
 * firewall anything about its health, which is worth surfacing rather than
 * hiding behind an empty card.
 */
export interface WatchdogCheck {
  name: 'engine_alive' | 'dataplane_rules' | 'pool_healthy' | 'egress_probe';
  ok: boolean;
  skipped?: boolean;
  detail?: string;
}

export interface WatchdogStatus {
  enabled: boolean;
  detail?: string;

  state?: 'healthy' | 'unhealthy' | 'unknown';
  at?: string;
  checks?: WatchdogCheck[];
  failing?: WatchdogCheck['name'][];

  fail_streak?: number;
  ok_streak?: number;
  fail_threshold?: number;
  recover_threshold?: number;

  liveness_ip?: string;
  liveness_up?: boolean;
  /* auto_failover=false means an unhealthy verdict is reported but the
   * liveness address stays up, so the firewall keeps diverting and the
   * operator has to cut over by hand. The card says so explicitly — a red
   * "unhealthy" with no cutover is otherwise easy to misread. */
  auto_failover?: boolean;

  last_transition?: string;
  last_error?: string;
}

/* ── Whitelist (GET / PUT /api/whitelist) ────────────────────────────────
 *
 * The routing decision, as the data plane sees it. Mirrors whitelistDTO in
 * internal/api/whitelist.go.
 *
 * PUT is a WHOLE-REPLACE operation, not a patch: whatever this object holds
 * after the edit becomes the entire whitelist. A UI that only sends the
 * fields it touched silently drops the rest (see the 2026-06-09 incident in
 * the handler comment, where `{}` cleared production).
 *
 * mode='overseas' means "no whitelist": every non-CN destination goes to
 * the pool. It is the only mode in which the match lists may be empty —
 * the handler rejects an empty whitelist-mode body on purpose.
 */
export interface Whitelist {
  mode: 'whitelist' | 'overseas' | string;
  /** Rule-set tags, always prefixed "geosite-". Must exist in the catalog. */
  geosites: string[];
  /** Rule-set tags, always prefixed "geoip-". Must exist in the catalog. */
  geoips: string[];
  /** Bare domain suffixes, e.g. "claude.ai". */
  domain_suffix: string[];
  /** CIDR or bare IPs; bare IPs are normalized to /32 or /128 server-side. */
  ip_cidr: string[];
  /** Intranet suffixes resolved via CN DoH, e.g. "+.corp.example.com". */
  fake_ip_skip: string[];
}

/* ── Rule-set catalog (GET /api/rule-sets) ───────────────────────────────
 *
 * installed = the .mrs/.srs is on disk; selected = the tag is in the current
 * whitelist. Selecting an uninstalled tag is legal: PUT fetches it on demand
 * (and can answer 502 if that fetch fails), which is why the UI warns about
 * a slower save rather than blocking the choice.
 */
export interface RuleSetEntry {
  name: string;
  url: string;
  category: string;
  installed: boolean;
  selected: boolean;
}

export interface RuleSetSide {
  catalog: RuleSetEntry[];
  domain_suffix_examples?: string[];
  ip_cidr_examples?: string[];
}

export interface RuleSets {
  geosites: RuleSetSide;
  geoips: RuleSetSide;
}

/* ── Node network (GET /api/node/network) ────────────────────────────────
 *
 * client_subnet is the diverted office segment: the source address the
 * firewall's PBR rule matches, and what iptables/nft/mihomo all key on.
 * Editing it fans out to /etc/turnout/env, nft.conf, turnout-nft.service and
 * the data plane, so a save is slow and briefly interrupts proxying.
 *
 * api_token_set is a boolean, never the token: the console needs to warn
 * when the control plane is unauthenticated, and must not receive the secret.
 */
export interface NodeNetwork {
  client_subnet: string;
  ingress_iface?: string;
  ingress_ip?: string;
  api_listen?: string;
  api_token_set: boolean;
}

/* ── Node signal (GET /api/node/signal) ──────────────────────────────────
 *
 * The watchdog's knobs. liveness_ip is the address bound to lo (or the
 * ingress NIC) that the firewall's IP-Link probe watches: present = Up,
 * absent = Down. It is consumed only by the watchdog goroutine, so a change
 * is "persist + restart turnout-gateway" — unlike client_subnet, nothing is
 * re-rendered into nft.conf or iptables.
 *
 * ingress_ip and return_gateway are surfaced so the UI can explain a
 * rejection: the address must collide with neither.
 */
export interface NodeSignal {
  liveness_ip: string;
  liveness_iface?: string;
  auto_failover: boolean;
  notify_on_state_change: boolean;
  ingress_ip?: string;
  return_gateway?: string;
}

/* ── Notifications (GET /api/notifications/status) ───────────────────────
 *
 * The Lark webhook is the only outbound channel; the JSONL log at
 * local_log_path records every attempt regardless of delivery outcome, so
 * "why didn't I get an alert" is answerable without depending on Lark.
 *
 * secret_configured is a boolean on purpose — the signing secret is never
 * returned. It lives in its own 0600 file, not in gateway.yaml.
 */
export interface NotificationsStatus {
  enabled: boolean;
  webhook_configured: boolean;
  signature_required: boolean;
  secret_configured: boolean;
  local_log_path?: string;
  dedup_window_sec?: number;
  aggregation_window_sec?: number;
  per_node_rate_limit_per_hour?: number;
  retry_attempts?: number;
}

/* One JSONL row. outcome is the verdict for this attempt:
 * queued | delivered | webhook_failed | dropped_dedup_or_rate_limit …
 * A row exists even when delivery failed — that is the point. */
export interface NotificationEntry {
  at: string;
  outcome: string;
  severity?: string;
  type?: string;
  node?: string;
  subject?: string;
  body?: string;
  extra?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

/* ── Ad blocking (GET /api/ad-block) ─────────────────────────────────────
 *
 * rule_set_installed is the difference between "blocking" and "believing you
 * are blocking": a missing .mrs makes mihomo log an error and keep running
 * with the rule matching nothing, so the switch would read as on while every
 * ad still loads. The API refuses to enable while this is false.
 */
export interface AdBlockState {
  enabled: boolean;
  rule_set_installed: boolean;
}
