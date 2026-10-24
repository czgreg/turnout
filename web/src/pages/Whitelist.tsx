import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Badge,
  Button,
  Card,
  Empty,
  InputTag,
  Message,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Tag,
} from '@arco-design/web-react';
import { IconSave, IconUndo } from '@arco-design/web-react/icon';
import * as api from '../api';
import type { Snapshot } from '../snapshot';
import type { AdultBlockState, AdBlockState, RuleSetEntry, Whitelist } from '../types';

/* Whitelist editor.
 *
 * The one thing this page must never do is send a partial object. PUT
 * /api/whitelist replaces every list wholesale, so the draft below is always
 * the FULL whitelist and the save path sends exactly what is on screen.
 * 2026-06-09: an automated caller sent `{}` and wiped production routing;
 * the handler now rejects empty whitelist-mode bodies, but the same class of
 * mistake from a UI would be "the operator edited one field and the other
 * four vanished". Hence: baseline + draft + an explicit diff in the confirm.
 *
 * Baseline reseeding: the console polls every 10s. The draft is reseeded from
 * the poll only while it is CLEAN, so a slow edit is never clobbered mid-type
 * by another operator's change — the dirty banner tells the user their view
 * is stale instead of silently reassigning it under them.
 */

const MODES = [
  {
    value: 'whitelist',
    title: '白名单（推荐）',
    desc: '只有命中下列规则的流量走海外池，其余一律交回防火墙直连。',
  },
  {
    value: 'overseas',
    title: '全量出海',
    desc: '不匹配任何白名单：所有非国内目标都走海外池。通常只在故障演练时使用。',
  },
];

const shortTag = (name: string) => name.replace(/^geosite-/, '').replace(/^geoip-/, '');

// Mirrors validateDomainSuffix in internal/api/whitelist.go. Checked here so a
// typo is caught before a save that would reload the data plane; the server
// remains the authority.
function suffixProblem(s: string): string {
  if (/\s/.test(s)) return '含空白';
  if (s.includes('://')) return '这是 URL，需要裸域名';
  if (s.includes('/')) return "含 '/'";
  if (!s.includes('.')) return "缺少 '.'";
  if (s.startsWith('.') || s.endsWith('.')) return '首尾不能有点';
  return '';
}

// Mirrors normalizeCIDRs' accept-set, loosely: the server parses with netip,
// which the browser cannot do exactly. A shape check catches "10.0.0.0/300"
// and stray text; anything subtler comes back as a 400 with the server text.
function cidrProblem(s: string): string {
  if (/\s/.test(s)) return '含空白';
  const [addr, bits] = s.split('/');
  if (bits !== undefined && !/^\d{1,3}$/.test(bits)) return '掩码长度不是数字';
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (v4) {
    const bad = v4.slice(1).find((o) => Number(o) > 255);
    if (bad !== undefined) return 'IPv4 段超过 255';
    if (bits !== undefined && Number(bits) > 32) return 'IPv4 掩码最大 32';
    return '';
  }
  if (addr.includes(':')) {
    if (bits !== undefined && Number(bits) > 128) return 'IPv6 掩码最大 128';
    return '';
  }
  return '既不是 IPv4/IPv6 地址也不是 CIDR';
}

const sorted = (xs: string[]) => xs.slice().sort((a, b) => a.localeCompare(b));

function diffList(label: string, before: string[], after: string[]) {
  const b = new Set(before);
  const a = new Set(after);
  const added = sorted(after.filter((x) => !b.has(x)));
  const removed = sorted(before.filter((x) => !a.has(x)));
  if (!added.length && !removed.length) return null;
  return { label, added, removed };
}

/* AdBlockCard — the ad-blocking switch.
 *
 * Kept out of the page's draft/baseline model on purpose: it is not part of
 * the whitelist document, it applies immediately, and it is not protected by
 * the "save the whole list" semantics. A toggle here re-renders and
 * hot-reloads mihomo (3–5s), no restart.
 *
 * The one thing this card must not hide: rule_set_installed=false means the
 * .mrs is not on disk. mihomo does NOT fail in that case — it logs an error
 * and keeps serving, with the rule matching nothing. So the server refuses to
 * enable (409) and the card says redeploy, rather than letting the operator
 * believe ads are being blocked.
 */
function AdBlockCard() {
  const [state, setState] = useState<AdBlockState | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    api
      .getAdBlock()
      .then(setState)
      .catch((e: Error) => setErr(e.message));
  }, []);

  const apply = async (enabled: boolean) => {
    setBusy(true);
    try {
      setState(await api.putAdBlock(enabled));
      setErr('');
      Message.success(enabled ? '已开启广告拦截' : '已关闭广告拦截');
    } catch (e) {
      setErr((e as Error).message);
      Message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const onChange = (next: boolean) => {
    if (busy || !state) return;
    if (!next) {
      apply(false);
      return;
    }
    Modal.confirm({
      title: '开启广告拦截？',
      content: (
        <div>
          <p>
            所有被引流终端对广告域名的请求会被直接拒绝。<b>没有按域名豁免的入口</b>，
            误杀的处置方式只有回到这里整体关闭。
          </p>
          <p className="small">
            保存后重载 mihomo，约 3–5 秒；只影响新建立的连接，已有连接不受影响。
          </p>
        </div>
      ),
      okText: '开启',
      cancelText: '取消',
      onOk: () => apply(true),
    });
  };

  return (
    <Card
      bordered={false}
      className="mb"
      title="广告拦截"
      extra={<span className="dim">PUT /api/ad-block</span>}
    >
      {err && <Alert className="mb" type="error" content={err} />}
      <Space>
        <Switch
          checked={!!state?.enabled}
          loading={busy}
          disabled={!state}
          onChange={onChange}
        />
        <span>{state?.enabled ? '已开启' : '已关闭'}</span>
        {state && !state.rule_set_installed && (
          <Tag color="orange">
            规则集缺失
            {state.missing?.length ? `：${state.missing.join('、')}` : ''}
            ，需重新部署后才能开启
          </Tag>
        )}
      </Space>
      <p className="dim mt">
        三份域名表：MetaCubeX <code>category-ads-all</code>（广告交易所）、anti-AD（中文向，约 11
        万条）、AdGuard cname-trackers（伪装成第一方域名的投放域名）。靠 TLS SNI / HTTP Host
        识别，终端零配置，对全部终端生效；规则位于 CN 直连之前。
        它只阻断广告<i>请求</i>——不会隐藏页面里的广告位，也不拦与正文同域的广告。
      </p>
    </Card>
  );
}

/* AdultBlockCard — the adult-content switch plus its exemption list.
 *
 * Same model as AdBlockCard: independent of the whitelist document, applies
 * immediately, hot-reloads mihomo. The exemption list exists because adult
 * lists produce false positives on health / education / art sites far more
 * often than ad lists do, and the alternative would be turning the whole
 * feature off.
 *
 * Copy must not over-claim: this is a DOMAIN-LIST match, not content
 * recognition. A site not in either list is not detected, and ECH defeats
 * the SNI the rule depends on.
 */
function AdultBlockCard() {
  const [state, setState] = useState<AdultBlockState | null>(null);
  const [allow, setAllow] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    api
      .getAdultBlock()
      .then((s) => {
        setState(s);
        setAllow(s.allow);
      })
      .catch((e: Error) => setErr(e.message));
  }, []);

  const allowDirty = useMemo(() => {
    if (!state) return false;
    const a = [...allow].sort();
    const b = [...state.allow].sort();
    return a.length !== b.length || a.some((x, i) => x !== b[i]);
  }, [allow, state]);

  const apply = async (enabled: boolean, nextAllow: string[]) => {
    setBusy(true);
    try {
      const next = await api.putAdultBlock(enabled, nextAllow);
      setState(next);
      setAllow(next.allow);
      setErr('');
      Message.success('成人内容封禁设置已保存');
    } catch (e) {
      setErr((e as Error).message);
      Message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const onChange = (next: boolean) => {
    if (busy || !state) return;
    if (next === state.enabled) return;
    if (!next) {
      apply(false, allow);
      return;
    }
    Modal.confirm({
      title: '开启成人内容封禁？',
      content: (
        <div>
          <p>
            所有被引流终端对名单内成人站点的请求会被直接拒绝。这是<b>域名名单匹配</b>，
            不是内容识别：名单外的站点不会被识别；浏览器启用 ECH 时也拦不到。
          </p>
          <p className="small">
            没有提示页，表现为连接被重置。规则位于 CN 直连之前，保存后重载 mihomo
            约 3–5 秒，只影响新建立的连接。
          </p>
        </div>
      ),
      okText: '开启',
      cancelText: '取消',
      onOk: () => apply(true, allow),
    });
  };

  return (
    <Card
      bordered={false}
      className="mb"
      title="成人内容封禁"
      extra={<span className="dim">PUT /api/adult-block</span>}
    >
      {err && <Alert className="mb" type="error" content={err} />}
      <Space>
        <Switch
          checked={!!state?.enabled}
          loading={busy}
          disabled={!state}
          onChange={onChange}
        />
        <span>{state?.enabled ? '已开启' : '已关闭'}</span>
        {state && !state.rule_set_installed && (
          <Tag color="orange">
            规则集缺失
            {state.missing?.length ? `：${state.missing.join('、')}` : ''}
            ，需重新部署后才能开启
          </Tag>
        )}
      </Space>
      <p className="dim mt">
        两份域名表：MetaCubeX <code>category-porn</code>（编译为{' '}
        <code>+.domain</code>，覆盖主域及全部子域）与 HaGeZi NSFW（约 9 万条，
        部署时归一化为 <code>+.domain</code>）。靠 TLS SNI / HTTP Host / QUIC
        识别，终端零配置，对全部被引流终端生效。
        它只按域名拦截，不做内容识别；平台内、图片搜索、即时通讯里的内容不在范围内。
      </p>
      <div className="wl-field">
        <label>误杀豁免（DOMAIN-SUFFIX）</label>
        <InputTag
          value={allow}
          onChange={(v) => setAllow(((v as string[]) || []).map((x) => x.trim()).filter(Boolean))}
          placeholder="输入域名后回车，例如 example-health.org"
          allowClear
          style={{ width: '100%' }}
        />
        <div style={{ marginTop: 8, textAlign: 'right' }}>
          <Button
            type="primary"
            icon={<IconSave />}
            loading={busy}
            disabled={!state || !allowDirty}
            onClick={() => apply(!!state?.enabled, allow)}
          >
            保存豁免
          </Button>
        </div>
        <p className="dim small">
          豁免规则排在 REJECT 之前，目标是 DIRECT（whitelist 模式）或普通海外出口（overseas
          模式）。不要把白名单里的域名放进来——它会被强制走直连。
        </p>
      </div>
    </Card>
  );
}

export default function WhitelistPage({
  snap,
  reload,
  onNavigate,
}: {
  snap: Snapshot;
  reload: () => Promise<void>;
  onNavigate: (k: string) => void;
}) {
  const base = snap.wl.data;
  const sets = snap.ruleSets.data;
  const [draft, setDraft] = useState<Whitelist | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  // Reseed while clean. `base` is a fresh object every poll, so compare by
  // value — reference identity would mark this dirty on every tick.
  useEffect(() => {
    if (!base || dirty) return;
    setDraft((cur) => (cur && sameWl(cur, base) ? cur : cloneWl(base)));
  }, [base, dirty]);

  const problems = useMemo(() => {
    if (!draft) return [] as string[];
    const out: string[] = [];
    draft.domain_suffix.forEach((s) => {
      const p = suffixProblem(s);
      if (p) out.push(`domain_suffix「${s}」：${p}`);
    });
    draft.ip_cidr.forEach((s) => {
      const p = cidrProblem(s);
      if (p) out.push(`ip_cidr「${s}」：${p}`);
    });
    return out;
  }, [draft]);

  const matchCount = draft
    ? draft.geosites.length + draft.geoips.length + draft.domain_suffix.length + draft.ip_cidr.length
    : 0;
  const emptyWhitelist = draft?.mode !== 'overseas' && matchCount === 0;

  // Class pools claim rule sets before the whitelist is rendered. Show that
  // mapping read-only and warn when an edit removes a claimed tag — the
  // backend still routes it (the pool's provider is emitted), so the operator
  // must not believe removal changes the class.
  const pools = snap.pools.data || [];
  const classOf = useMemo(() => {
    const m: Record<string, string> = {};
    pools.forEach((p) => (p.rule_sets || []).forEach((r) => (m[r] = p.name)));
    return m;
  }, [pools]);
  const removedClassRules = useMemo(() => {
    if (!draft || !base) return [] as string[];
    const claimed = new Set<string>();
    pools.forEach((p) => (p.rule_sets || []).forEach((r) => claimed.add(r)));
    return Array.from(claimed).filter((r) => base.geosites.includes(r) && !draft.geosites.includes(r));
  }, [pools, draft, base]);

  const patch = (p: Partial<Whitelist>) => {
    setDraft((cur) => (cur ? { ...cur, ...p } : cur));
    setDirty(true);
  };

  const reset = () => {
    if (base) setDraft(cloneWl(base));
    setDirty(false);
  };

  const confirmSave = () => {
    if (!draft) return;
    const diffs = [
      diffList('geosites', base?.geosites || [], draft.geosites),
      diffList('geoips', base?.geoips || [], draft.geoips),
      diffList('domain_suffix', base?.domain_suffix || [], draft.domain_suffix),
      diffList('ip_cidr', base?.ip_cidr || [], draft.ip_cidr),
      diffList('fake_ip_skip', base?.fake_ip_skip || [], draft.fake_ip_skip),
    ].filter((d): d is NonNullable<typeof d> => d !== null);
    const modeChanged = base?.mode !== draft.mode;
    const needFetch = newTagsNotOnDisk(draft, sets);

    Modal.confirm({
      title: '整体替换分流白名单？',
      content: (
        <div className="wl-confirm">
          <p>
            这是一个<b>整体替换</b>操作：提交后白名单就是下面这份内容，其余条目会消失。
          </p>
          {modeChanged && (
            <p>
              分流模式：<Tag size="small">{base?.mode || '—'}</Tag> → <Tag size="small" color="orange">{draft.mode}</Tag>
            </p>
          )}
          {draft.mode === 'overseas' && (
            <Alert
              type="warning"
              title="全量出海"
              content="所有非国内目标都会被送进海外池。办公网的内网系统若不在 fake_ip_skip 里，可能因 DNS 走海外 DoH 而解析失败。"
            />
          )}
          {diffs.length === 0 && !modeChanged ? (
            <p className="dim">规则本身没有变化（只有顺序或大小写差异会被服务端规范化）。</p>
          ) : (
            diffs.map((d) => (
              <div key={d.label} className="wl-diff">
                <span className="mono">{d.label}</span>
                {d.added.map((x) => (
                  <Tag key={'+' + x} color="green" size="small">
                    + {x}
                  </Tag>
                ))}
                {d.removed.map((x) => (
                  <Tag key={'-' + x} color="red" size="small">
                    − {x}
                  </Tag>
                ))}
              </div>
            ))
          )}
          {needFetch.length > 0 && (
            <Alert
              type="info"
              className="mt"
              content={`${needFetch.join('、')} 尚未下载，保存时会先拉取规则集（最坏 60 秒），拉取失败则整次保存失败、白名单不变。`}
            />
          )}
          <p className="mt">
            保存会重启 mihomo，约 <b>3–5 秒</b>连接中断。期间已建立的连接会断开。
          </p>
        </div>
      ),
      okText: '替换并重载',
      onOk: async () => {
        setSaving(true);
        try {
          const saved = await api.putWhitelist(draft);
          setDraft(cloneWl(saved));
          setDirty(false);
          Message.success('白名单已保存，数据面已重载');
          await reload();
        } catch (e) {
          Message.error('保存失败：' + (e as Error).message);
        } finally {
          setSaving(false);
        }
      },
    });
  };

  if (snap.wl.err) {
    return (
      <div className="page">
        <Alert type="error" title="读取分流白名单失败" content={snap.wl.err} />
      </div>
    );
  }
  if (!draft) {
    return (
      <div className="page">
        <Card bordered={false}>
          <Empty description={snap.updatedAt ? '尚无白名单数据' : '加载中…'} />
        </Card>
      </div>
    );
  }

  const geoGroups = groupCatalog(sets?.geosites?.catalog || []);
  const ipGroups = groupCatalog(sets?.geoips?.catalog || []);

  return (
    <div className="page">
      <Alert
        type="warning"
        className="mb"
        title="改这里等于改全公司的分流结果"
        content="保存会整体替换白名单并重载 mihomo（3–5 秒中断）。不命中的流量一律交回防火墙直连；漏掉一个域名，表现不是报错，而是「那个网站打不开」。"
      />

      {dirty && (
        <Alert
          type="info"
          className="mb"
          title="有未保存的改动"
          content={
            <Space>
              <span>
                页面上的内容是你的草稿，节点上仍是上一次保存的版本。自动刷新不会再覆盖它。
              </span>
              <Button size="small" icon={<IconUndo />} onClick={reset}>
                丢弃改动
              </Button>
            </Space>
          }
        />
      )}

      <Card bordered={false} className="mb" title="分流模式">
        <Radio.Group
          type="button"
          value={draft.mode}
          onChange={(v) => patch({ mode: v as Whitelist['mode'] })}
        >
          {MODES.map((m) => (
            <Radio key={m.value} value={m.value}>
              {m.title}
            </Radio>
          ))}
        </Radio.Group>
        <p className="dim mt">{MODES.find((m) => m.value === draft.mode)?.desc}</p>
        {emptyWhitelist && (
          <Alert
            type="error"
            className="mt"
            content="白名单模式下至少要有一条规则（geosite / geoip / domain_suffix / ip_cidr 任意一条），否则服务端会拒绝保存。要清空请先切到「全量出海」。"
          />
        )}
      </Card>

      {pools.length > 0 && (
        <Card
          bordered={false}
          className="mb"
          title="出口分组（gateway.yaml）"
          extra={<span className="dim">只读 · 修改请编辑 pools</span>}
        >
          <p className="dim small mb">
            分类池优先 claim 下列规则集/域名；白名单命中它们时走对应分类，不再走默认「其他」类。
          </p>
          {pools.map((p) => (
            <div key={p.name} className="wl-field">
              <label>
                <span className="mono">{p.name}</span>{' '}
                <Tag size="small">{p.per_terminal ? '每终端固定 IP' : '共享出口'}</Tag>{' '}
                <Tag size="small">size {p.size || '全局 K'}</Tag>
              </label>
              <div className="dim small">
                node_pattern: <span className="mono">{p.node_pattern || '继承全局'}</span>
              </div>
              <div>
                {(p.rule_sets || []).map((r) => (
                  <Tag key={r} size="small" style={{ marginRight: 4 }}>{shortTag(r)}</Tag>
                ))}
                {(p.rule_lists || []).map((l) => (
                  <Tag key={l.tag} size="small" style={{ marginRight: 4 }}>{l.tag}（外部列表）</Tag>
                ))}
                {(p.domain_suffix || []).map((d) => (
                  <Tag key={d} size="small" style={{ marginRight: 4 }}>{d}</Tag>
                ))}
              </div>
            </div>
          ))}
        </Card>
      )}

      {removedClassRules.length > 0 && (
        <Alert
          type="warning"
          className="mb"
          title="分类池规则被移出白名单"
          content={`${removedClassRules.map(shortTag).join('、')} 由分类池 claim；移出白名单不会改变分组路由（后端仍会为分类池的 rule_sets 发 provider）。要改分组请编辑 gateway.yaml 的 pools。`}
        />
      )}

      <AdBlockCard />
      <AdultBlockCard />

      <Card
        bordered={false}
        className="mb"
        title="域名侧"
        extra={<span className="dim">命中任意一条即走海外池</span>}
      >
        <div className="wl-field">
          <label>geosite 规则集</label>
          <Select
            mode="multiple"
            allowClear
            placeholder="选择应用/站点类别，例如 google、openai"
            value={draft.geosites}
            onChange={(v) => patch({ geosites: dedupe((v as string[]) || []) })}
            style={{ width: '100%' }}
          >
            {geoGroups.map((g) => (
              <Select.OptGroup key={g.category} label={g.category}>
                {g.items.map((it) => (
                  <Select.Option key={it.name} value={it.name}>
                    <span className="wl-opt">
                      <span className="mono">{shortTag(it.name)}</span>
                      {classOf[it.name] && <span className="wl-opt-flag">{classOf[it.name]}</span>}
                      {!it.installed && <span className="wl-opt-flag">未下载</span>}
                    </span>
                  </Select.Option>
                ))}
              </Select.OptGroup>
            ))}
          </Select>
          <div className="dim small">
            规则集来自 MetaCubeX；「未下载」的项在首次保存时自动拉取。当前 {draft.geosites.length} 条。
          </div>
        </div>

        <div className="wl-field">
          <label>domain_suffix（裸域名）</label>
          <InputTag
            value={draft.domain_suffix}
            onChange={(v) => patch({ domain_suffix: dedupe(((v as string[]) || []).map((s) => s.trim())) })}
            placeholder="输入域名后回车，例如 claude.ai"
            allowClear
            saveOnBlur
          />
          <div className="dim small">
            子域名自动包含（claude.ai 也覆盖 api.claude.ai）。只写域名，不带协议和路径。
            {sets?.geosites?.domain_suffix_examples?.length ? (
              <> 常用：{sets.geosites.domain_suffix_examples.slice(0, 6).join('、')}</>
            ) : null}
          </div>
        </div>
      </Card>

      <Card
        bordered={false}
        className="mb"
        title="IP 侧"
        extra={<span className="dim">给跳过 DNS 的应用用（Telegram MTProto 等）</span>}
      >
        <div className="wl-field">
          <label>geoip 规则集</label>
          <Select
            mode="multiple"
            allowClear
            placeholder="选择 IP 归属类别，例如 telegram"
            value={draft.geoips}
            onChange={(v) => patch({ geoips: dedupe((v as string[]) || []) })}
            style={{ width: '100%' }}
          >
            {ipGroups.map((g) => (
              <Select.OptGroup key={g.category} label={g.category}>
                {g.items.map((it) => (
                  <Select.Option key={it.name} value={it.name}>
                    <span className="wl-opt">
                      <span className="mono">{shortTag(it.name)}</span>
                      {!it.installed && <span className="wl-opt-flag">未下载</span>}
                    </span>
                  </Select.Option>
                ))}
              </Select.OptGroup>
            ))}
          </Select>
          <div className="dim small">当前 {draft.geoips.length} 条。</div>
        </div>

        <div className="wl-field">
          <label>ip_cidr</label>
          <InputTag
            value={draft.ip_cidr}
            onChange={(v) => patch({ ip_cidr: dedupe(((v as string[]) || []).map((s) => s.trim())) })}
            placeholder="输入 CIDR 或单个 IP 后回车，例如 149.154.0.0/16"
            allowClear
            saveOnBlur
          />
          <div className="dim small">
            单个 IP 会被服务端补成 /32（IPv6 为 /128）。
            {sets?.geoips?.ip_cidr_examples?.length ? (
              <> 示例：{sets.geoips.ip_cidr_examples.slice(0, 4).join('、')}</>
            ) : null}
          </div>
        </div>
      </Card>

      <Card
        bordered={false}
        className="mb"
        title="内网域名（fake_ip_skip）"
        extra={<span className="dim">这些后缀走国内 DoH 解析</span>}
      >
        <div className="wl-field">
          <InputTag
            value={draft.fake_ip_skip}
            onChange={(v) => patch({ fake_ip_skip: dedupe(((v as string[]) || []).map((s) => s.trim())) })}
            placeholder="输入内网域名后缀后回车，例如 corp.example.com"
            allowClear
            saveOnBlur
          />
          <div className="dim small">
            默认 nameserver 是海外 DoH，对纯内网域名没有记录。列出这里的后缀会改用国内 DoH 解析，并在 DNS 侧放行。
            服务端会统一规范化为 <span className="mono">+.example.com</span> 形式。
          </div>
        </div>
      </Card>

      {problems.length > 0 && (
        <Alert
          type="error"
          className="mb"
          title={`${problems.length} 条格式问题，保存会被服务端拒绝`}
          content={
            <ul className="wl-problems">
              {problems.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          }
        />
      )}

      <Card bordered={false}>
        <Space>
          <Button
            type="primary"
            icon={<IconSave />}
            loading={saving}
            disabled={!dirty || emptyWhitelist || problems.length > 0}
            onClick={confirmSave}
          >
            {saving ? '保存并重载中…' : '保存并重载'}
          </Button>
          <Button icon={<IconUndo />} disabled={!dirty || saving} onClick={reset}>
            丢弃改动
          </Button>
          <Button type="text" onClick={() => onNavigate('terminal')}>
            保存后用「终端查询」验证某个 IP 的实际出口 →
          </Button>
        </Space>
        {!dirty && (
          <span className="dim" style={{ marginLeft: 12 }}>
            <Badge status="success" text="与服务端一致" />
          </span>
        )}
      </Card>
    </div>
  );
}

/* ── helpers ───────────────────────────────────────────────────────────── */

const cloneWl = (w: Whitelist): Whitelist => ({
  mode: w.mode || 'whitelist',
  geosites: [...(w.geosites || [])],
  geoips: [...(w.geoips || [])],
  domain_suffix: [...(w.domain_suffix || [])],
  ip_cidr: [...(w.ip_cidr || [])],
  fake_ip_skip: [...(w.fake_ip_skip || [])],
});

const sameWl = (a: Whitelist, b: Whitelist) =>
  a.mode === b.mode &&
  a.geosites.join('\n') === b.geosites.join('\n') &&
  a.geoips.join('\n') === b.geoips.join('\n') &&
  a.domain_suffix.join('\n') === b.domain_suffix.join('\n') &&
  a.ip_cidr.join('\n') === b.ip_cidr.join('\n') &&
  a.fake_ip_skip.join('\n') === b.fake_ip_skip.join('\n');

// Client-side dedupe only. The server normalizes too, but doing it here keeps
// the draft (and the confirm diff) honest about what the operator actually
// wrote. Order is preserved — the renderer emits rules in this order.
const dedupe = (xs: string[]) => {
  const seen = new Set<string>();
  return xs.filter((x) => {
    if (!x || seen.has(x)) return false;
    seen.add(x);
    return true;
  });
};

const findEntry = (catalog: RuleSetEntry[] | undefined, name: string) =>
  catalog?.find((e) => e.name === name);

function groupCatalog(catalog: RuleSetEntry[]) {
  const m = new Map<string, RuleSetEntry[]>();
  for (const it of catalog) {
    const cat = it.category || 'other';
    if (!m.has(cat)) m.set(cat, []);
    m.get(cat)!.push(it);
  }
  return Array.from(m.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, items]) => ({ category, items }));
}

function newTagsNotOnDisk(w: Whitelist, sets: { geosites?: { catalog: RuleSetEntry[] }; geoips?: { catalog: RuleSetEntry[] } } | undefined) {
  const out: string[] = [];
  const check = (tags: string[], catalog: RuleSetEntry[] | undefined) => {
    for (const t of tags) {
      const e = findEntry(catalog, t);
      if (e && !e.installed) out.push(shortTag(t));
    }
  };
  check(w.geosites, sets?.geosites?.catalog);
  check(w.geoips, sets?.geoips?.catalog);
  return out;
}
