// Vite plugin that answers /healthz and /api/* from mock/data.ts, for both
// `vite --mode mock` (dev) and `vite preview --mode mock` (built bundle).
// Subscription writes mutate in-memory state and sleep like a real refresh,
// so loading states and confirm flows can be exercised without a node.
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Connect, Plugin } from 'vite';
import * as data from './data';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function readBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        resolve({});
      }
    });
  });
}

function send(res: ServerResponse, status: number, body?: unknown) {
  if (body === undefined) {
    res.statusCode = status;
    res.end();
    return;
  }
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

function handler(): Connect.NextHandleFunction {
  let subs = data.initialSubs();
  let interval = 0;
  let refreshing = false;
  let wl = data.whitelist();
  // Mutable so PUT /api/node/network can be exercised in mock mode. Starts
  // unauthenticated (api_token_set=false) so the page's warning renders.
  let network = data.network();
  let signal = data.signal();
  let notif = data.notifications();
  let notifLog = data.notificationLog();
  let adBlock = data.adBlock();

  return async (req, res, next) => {
    const url = new URL(req.url || '/', 'http://mock');
    const path = url.pathname;
    const method = req.method || 'GET';
    if (path !== '/healthz' && !path.startsWith('/api/')) return next();

    if (path === '/healthz') return send(res, 200, data.healthz());
    if (path === '/api/status') return send(res, 200, data.status(subs));
    if (path === '/api/proxies/active') return send(res, 200, data.active(subs));
    if (path === '/api/pools') return send(res, 200, data.pools());
    if (path === '/api/nodes/health') return send(res, 200, data.nodesHealth());
    if (path === '/api/pool/transitions') return send(res, 200, data.transitions());
    if (path === '/api/pool/terminal') {
      const ip = url.searchParams.get('ip');
      if (!ip) return send(res, 400, { error: 'missing ?ip= query parameter' });
      await sleep(250);
      return send(res, 200, data.terminal(ip));
    }

    if (path === '/api/subscribe/refresh-interval') {
      if (method === 'PUT') interval = Number((await readBody(req)).seconds) || 0;
      return send(res, 200, { seconds: interval });
    }
    if (path === '/api/subscribe/refresh' && method === 'POST') {
      if (refreshing) return send(res, 409, { error: 'refresh already in progress' });
      refreshing = true;
      await sleep(2500);
      refreshing = false;
      return send(res, 200, { ok: true });
    }

    if (path === '/api/subscriptions') {
      if (method === 'POST') {
        const b = await readBody(req);
        if (subs.some((s) => s.name === b.name)) return send(res, 409, { error: 'subscription already exists' });
        await sleep(1500);
        subs = [
          ...subs,
          {
            name: b.name,
            url: String(b.url).replace(/token=(\w{4})\w+(\w{4})/, 'token=$1***$2'),
            enabled: true,
            format: b.format || 'auto',
            user_agent: b.user_agent || undefined,
            nodes_count: 12,
            last_refresh: new Date().toISOString(),
          },
        ];
        return send(res, 201, subs);
      }
      return send(res, 200, subs);
    }
    const m = path.match(/^\/api\/subscriptions\/(.+)$/);
    if (m) {
      const name = decodeURIComponent(m[1]);
      if (!subs.some((s) => s.name === name)) return send(res, 404, { error: 'subscription not found' });
      await sleep(1500);
      if (method === 'DELETE') {
        subs = subs.filter((s) => s.name !== name);
        return send(res, 204);
      }
      if (method === 'PUT') {
        const b = await readBody(req);
        subs = subs.map((s) => (s.name === name ? { ...s, user_agent: b.user_agent || undefined } : s));
        return send(res, 200, subs);
      }
    }
    if (path === '/api/whitelist') {
      if (method === 'GET') return send(res, 200, wl);
      if (method === 'PUT') {
        const b = await readBody(req);
        // Mirror the handler's empty-body guard: `{}` is rejected, and the
        // message is the one the real server sends so the UI path is tested.
        const empty =
          !b.geosites?.length && !b.geoips?.length && !b.domain_suffix?.length && !b.ip_cidr?.length;
        if (String(b.mode || wl.mode) !== 'overseas' && empty) {
          return send(res, 400, {
            error:
              'whitelist body has no match entries — set mode="overseas" to intentionally clear, or include at least one of geosites/geoips/domain_suffix/ip_cidr',
          });
        }
        await sleep(3000); // mihomo reload
        wl = {
          mode: b.mode || wl.mode,
          geosites: b.geosites || [],
          geoips: b.geoips || [],
          // Server-side normalization, visible here so the UI's "saved value
          // wins over the draft" behaviour can be exercised in mock mode.
          domain_suffix: (b.domain_suffix || []).map((s: string) => s.toLowerCase()),
          ip_cidr: (b.ip_cidr || []).map((s: string) => (s.includes('/') ? s : s + '/32')),
          fake_ip_skip: (b.fake_ip_skip || []).map((s: string) => (s.startsWith('+.') ? s : '+.' + s)),
        };
        return send(res, 200, wl);
      }
    }
    if (path === '/api/rule-sets') return send(res, 200, data.ruleSets(wl));

    if (path === '/api/watchdog/status') return send(res, 200, data.watchdogStatus(signal.auto_failover));

    if (path === '/api/notifications/status') return send(res, 200, notif);

    if (path === '/api/ad-block') {
      if (method === 'PUT') {
        const b = await readBody(req);
        if (b.enabled === undefined) return send(res, 400, { error: 'enabled field is required' });
        if (b.enabled && !adBlock.rule_set_installed) {
          return send(res, 409, { error: 'cannot enable ad blocking: category-ads-all.mrs is not on disk' });
        }
        await sleep(2500); // mihomo re-render + hot reload
        adBlock = { ...adBlock, enabled: !!b.enabled };
        return send(res, 200, adBlock);
      }
      return send(res, 200, adBlock);
    }

    if (path === '/api/notifications/lark') {
      if (method === 'POST') {
        const b = await readBody(req);
        const url = String(b.webhook_url || '');
        const sigRequired = b.signature_required !== undefined ? !!b.signature_required : true;
        // Mirror the server's two guards so the UI's error path is exercised.
        if (!url) return send(res, 400, { error: 'webhook_url required' });
        if (sigRequired && !b.secret && !notif.secret_configured) {
          return send(res, 400, { error: 'secret required when signature_required=true (default)' });
        }
        notif = {
          ...notif,
          enabled: true,
          webhook_configured: true,
          signature_required: sigRequired,
          secret_configured: sigRequired ? true : notif.secret_configured,
        };
        return send(res, 200, notif);
      }
      if (method === 'DELETE') {
        notif = { ...notif, enabled: false, webhook_configured: false, secret_configured: false };
        return send(res, 200, notif);
      }
    }

    if (path === '/api/notifications/test') {
      if (!notif.webhook_configured) {
        return send(res, 502, { ok: false, error: 'mock: webhook not configured' });
      }
      notifLog = [
        {
          at: new Date().toISOString(),
          outcome: 'delivered',
          severity: 'info',
          type: 'test',
          subject: 'turnout-gateway 测试消息',
          body: '如果看到这条消息，说明 webhook 配置正确。',
        },
        ...notifLog,
      ];
      return send(res, 200, { ok: true });
    }

    if (path === '/api/notifications/recent') {
      return send(res, 200, { entries: notifLog, limit: notifLog.length });
    }

    if (path === '/api/node/signal') {
      if (method === 'PUT') {
        const b = await readBody(req);
        if (b.liveness_ip !== undefined) {
          const ip = String(b.liveness_ip).trim();
          if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
            return send(res, 400, { error: `liveness_ip ${JSON.stringify(ip)} is not a valid IPv4 address` });
          }
          if (ip === signal.ingress_ip) {
            return send(res, 400, { error: 'liveness_ip must not equal ingress_ip — withdrawing it would also drop SSH and the API' });
          }
          signal = { ...signal, liveness_ip: ip };
        }
        if (b.auto_failover !== undefined) signal = { ...signal, auto_failover: !!b.auto_failover };
        if (b.notify_on_state_change !== undefined) {
          signal = { ...signal, notify_on_state_change: !!b.notify_on_state_change };
        }
        // The real handler returns before the restart it schedules.
        return send(res, 200, { restart: 'scheduled', note: 'mock: no actual restart' });
      }
      return send(res, 200, signal);
    }

    if (path === '/api/node/network') {
      if (method === 'PUT') {
        const b = await readBody(req);
        const next = String(b.client_subnet || '');
        // Same guard the server applies first: a CIDR, network address, /8../31.
        if (!/^\d{1,3}(\.\d{1,3}){3}\/([89]|[12]\d|3[01])$/.test(next)) {
          return send(res, 400, { error: `client_subnet ${JSON.stringify(next)} is not a usable CIDR` });
        }
        await sleep(2500); // env + nft.conf + turnout-nft restart + mihomo reload
        const previous = network.client_subnet;
        network = { ...network, client_subnet: next };
        return send(res, 200, { client_subnet: next, previous, applied: true });
      }
      return send(res, 200, network);
    }

    return send(res, 404, { error: 'mock: no handler for ' + method + ' ' + path });
  };
}

export function mockApi(): Plugin {
  return {
    name: 'turnout-mock-api',
    configureServer(server) {
      server.middlewares.use(handler());
    },
    configurePreviewServer(server) {
      server.middlewares.use(handler());
    },
  };
}
