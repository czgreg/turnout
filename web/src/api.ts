/* Control-plane API client.
 *
 * 设计约束（来自 docs/api.md，改动前先读那份文档）：
 *  1. GET /api/subscriptions 返回的 url 是**脱敏**的（token=abcd***ef01）。
 *     PUT 又要求 url 非空。所以编辑表单绝不回填脱敏 URL —— 那会把
 *     星号写进生产配置。要改 URL 必须粘贴完整新 URL（见 pages/Subscriptions）。
 *  2. 订阅的增删改、以及 POST /api/subscribe/refresh 都会重载 mihomo
 *     （约 3–5 秒中断），所以这些操作一律先确认。请求本身要慢得多：
 *     每个订阅最多两次 fetch（UA 回退探测），实测冷刷新 17–30s。确认
 *     文案必须说出这个时长 —— 操作者以为卡死而掐断连接，正是
 *     2026-09-24 那次配置落盘但 reload 没跑的起因。
 *  3. token 只放在这个模块的内存变量里。不进 web storage —— 这个页面
 *     可能开在共享的运维机上，而 token 能读到带凭据的订阅 URL。
 *
 * Endpoint paths are written as single-quoted literals on purpose:
 * internal/api/ui_test.go extracts them and asserts each one is registered
 * in api.go, so a renamed route fails `go test` instead of 404-ing here.
 */
import type {
  Active,
  AdBlockState,
  Healthz,
  NodeNetwork,
  NodeSignal,
  NodesHealth,
  NotificationEntry,
  NotificationsStatus,
  Pools,
  RefreshInterval,
  RuleSets,
  Status,
  Subscription,
  TerminalAssignment,
  Transitions,
  WatchdogStatus,
  Whitelist,
} from './types';

let base = '';
let token = '';

export function connect(nextBase: string, nextToken: string) {
  base = nextBase.trim().replace(/\/+$/, '');
  token = nextToken;
}

export function disconnect() {
  base = '';
  token = '';
}

export function currentBase() {
  return base;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  if (opts.body) headers['Content-Type'] = 'application/json';

  const res = await fetch(base + path, { ...opts, headers });
  if (res.status === 401) throw new ApiError(401, '401 未授权 —— token 不正确');
  if (res.status === 204) return null as T;

  const text = await res.text();
  if (!res.ok) {
    // Errors are either http.Error plain text or writeJSON {"error": "..."}.
    let msg = text.split('\n')[0].trim() || res.statusText;
    try {
      const body = JSON.parse(text);
      if (body && typeof body.error === 'string') msg = body.error;
    } catch {
      /* plain text */
    }
    throw new ApiError(res.status, `${res.status} ${msg}`);
  }
  if (!text) return null as T;
  return JSON.parse(text) as T;
}

const json = (body: unknown): RequestInit => ({ body: JSON.stringify(body) });

/** /healthz is unauthenticated and answers 503 with a body when an assertion fails. */
export async function getHealthz(): Promise<{ httpStatus: number; body: Healthz | null }> {
  const res = await fetch(base + '/healthz');
  let body: Healthz | null = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON: older binary */
  }
  return { httpStatus: res.status, body };
}

/**
 * /api/watchdog/status answers 503 WITH a body when the verdict is
 * unhealthy, and 200 with body.state='unknown' before the first check round.
 *
 * So this must not go through request(): that throws on non-2xx and the body
 * with it, which would blank the health card at exactly the moment it has
 * something important to say. Mirrors getHealthz — status and body are
 * returned together and the caller decides.
 */
export async function getWatchdogStatus(): Promise<{ httpStatus: number; body: WatchdogStatus | null }> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = 'Bearer ' + token;
  const res = await fetch(base + '/api/watchdog/status', { headers });
  let body: WatchdogStatus | null = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON: older binary */
  }
  return { httpStatus: res.status, body };
}

export const getStatus = () => request<Status>('/api/status');
export const getActive = () => request<Active>('/api/proxies/active');
/** Read-only class-pool config (gateway.yaml `pools:`); members are in Active. */
export const getPools = () => request<Pools>('/api/pools');
export const getNodesHealth = () => request<NodesHealth>('/api/nodes/health');
export const getSubscriptions = () => request<Subscription[]>('/api/subscriptions');
export const getRefreshInterval = () => request<RefreshInterval>('/api/subscribe/refresh-interval');
export const getTransitions = (limit = 100) =>
  request<Transitions>('/api/pool/transitions?limit=' + limit);
export const getTerminal = (ip: string) =>
  request<TerminalAssignment>('/api/pool/terminal?ip=' + encodeURIComponent(ip));

export const addSubscription = (sub: { name: string; url: string; format: string; user_agent: string }) =>
  request<Subscription[]>('/api/subscriptions', { method: 'POST', ...json(sub) });

export const updateSubscription = (name: string, sub: { url: string; user_agent: string }) =>
  request<unknown>('/api/subscriptions/' + encodeURIComponent(name), { method: 'PUT', ...json(sub) });

export const deleteSubscription = (name: string) =>
  request<null>('/api/subscriptions/' + encodeURIComponent(name), { method: 'DELETE' });

export const refreshSubscriptions = () =>
  request<{ ok: boolean }>('/api/subscribe/refresh', { method: 'POST' });

export const setRefreshInterval = (seconds: number) =>
  request<RefreshInterval>('/api/subscribe/refresh-interval', { method: 'PUT', ...json({ seconds }) });

/**
 * Current routing decision + the rule-set catalog.
 *
 * putWhitelist sends the FULL object, never a delta: the handler replaces
 * every list wholesale. It also reloads mihomo (3–5s) and may spend up to
 * 60s fetching rule-sets that aren't on disk yet, so the caller confirms
 * first — same reasoning as the subscription writes above.
 */
export const getWhitelist = () => request<Whitelist>('/api/whitelist');
export const putWhitelist = (wl: Whitelist) =>
  request<Whitelist>('/api/whitelist', { method: 'PUT', ...json(wl) });
export const getRuleSets = () => request<RuleSets>('/api/rule-sets');

/**
 * Ad blocking — one REJECT rule ahead of the CN-direct line.
 *
 * putAdBlock re-renders and hot-reloads mihomo (3–5s), no restart. It can
 * answer 409 when the rule-set is not on disk; the server refuses to turn the
 * switch on in that state rather than block nothing silently.
 */
export const getAdBlock = () => request<AdBlockState>('/api/ad-block');
export const putAdBlock = (enabled: boolean) =>
  request<AdBlockState>('/api/ad-block', { method: 'PUT', ...json({ enabled }) });

/**
 * Node network — the diverted office segment.
 *
 * putNodeNetwork is NOT a plain config write: the node re-renders nft.conf,
 * restarts turnout-nft.service (a short gap where traffic is not proxied)
 * and hot-reloads mihomo. The caller confirms before saving; a 500 carries
 * `persisted` because gateway.yaml may hold the new value while the live
 * rules are still the old ones.
 */
export const getNodeNetwork = () => request<NodeNetwork>('/api/node/network');
export const putNodeNetwork = (clientSubnet: string) =>
  request<{ client_subnet: string; previous: string; applied: boolean }>('/api/node/network', {
    method: 'PUT',
    ...json({ client_subnet: clientSubnet }),
  });

/**
 * Watchdog knobs (liveness_ip / auto_failover / notify_on_state_change).
 *
 * putNodeSignal returns before the change takes effect: turnout-gateway
 * schedules its own restart a couple of seconds out, so the POST-save state
 * is only visible once the console's next poll succeeds. The caller should
 * expect a failed poll or two rather than treat them as an error.
 */
export const getNodeSignal = () => request<NodeSignal>('/api/node/signal');
export const putNodeSignal = (patch: {
  liveness_ip?: string;
  liveness_iface?: string;
  auto_failover?: boolean;
  notify_on_state_change?: boolean;
}) => request<{ restart: string; removed_old?: string; note?: string }>('/api/node/signal', {
  method: 'PUT',
  ...json(patch),
});

/**
 * Lark notification channel.
 *
 * setLark persists the webhook URL to gateway.yaml and the signing secret to
 * its own 0600 file — the secret never comes back from the API, only
 * `secret_configured: boolean`. signature_required defaults to TRUE on the
 * server, so a secret is mandatory unless the caller explicitly disables
 * signing; the UI mirrors that default rather than letting the operator
 * discover it as a 400.
 */
export const getNotificationsStatus = () =>
  request<NotificationsStatus>('/api/notifications/status');
export const setLark = (body: { webhook_url: string; secret?: string; signature_required?: boolean }) =>
  request<NotificationsStatus>('/api/notifications/lark', { method: 'POST', ...json(body) });
export const clearLark = () =>
  request<NotificationsStatus>('/api/notifications/lark', { method: 'DELETE' });
export const testNotification = () =>
  request<{ ok: boolean }>('/api/notifications/test', { method: 'POST' });
export const getNotificationLog = (limit = 50) =>
  request<{ entries: NotificationEntry[]; limit: number }>(
    '/api/notifications/recent?limit=' + limit,
  );
