import type {
  Active,
  Healthz,
  NodeNetwork,
  NodeSignal,
  NodesHealth,
  RefreshInterval,
  RuleSets,
  Status,
  Subscription,
  Transitions,
  WatchdogStatus,
  Whitelist,
} from './types';

/** One endpoint's latest result: data on success, err (and HTTP status) on failure. */
export interface Slot<T> {
  data?: T;
  err?: string;
  status?: number;
}

/** Everything one polling round fetched. Pages render from this alone. */
export interface Snapshot {
  /** null = /healthz unreachable; undefined = not polled yet. */
  healthz?: { httpStatus: number; body: Healthz | null } | null;
  status: Slot<Status>;
  active: Slot<Active>;
  health: Slot<NodesHealth>;
  subs: Slot<Subscription[]>;
  interval: Slot<RefreshInterval>;
  /**
   * Routing decision + rule-set catalog. The whitelist page keeps its own
   * editable draft; these slots are the baseline it diffs against and reseeds
   * from after a successful save.
   */
  wl: Slot<Whitelist>;
  ruleSets: Slot<RuleSets>;
  trans: Slot<Transitions>;
  /** Diverted office segment. The network page edits client_subnet from here. */
  network: Slot<NodeNetwork>;
  /** Watchdog knobs — liveness address + failover/notify switches. */
  signal: Slot<NodeSignal>;
  /**
   * Watchdog health. Same shape as healthz rather than Slot<T>: the endpoint
   * answers 503 WITH a full body when the verdict is unhealthy, so the body
   * has to survive a non-OK status. null = endpoint unreachable.
   */
  watchdog?: { httpStatus: number; body: WatchdogStatus | null } | null;
  updatedAt?: Date;
}

export const emptySnapshot: Snapshot = {
  status: {},
  active: {},
  health: {},
  subs: {},
  interval: {},
  wl: {},
  ruleSets: {},
  trans: {},
  network: {},
  signal: {},
};
