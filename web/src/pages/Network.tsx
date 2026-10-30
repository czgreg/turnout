import { useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Grid,
  Input,
  Message,
  Modal,
  Space,
  Switch,
  Tag,
} from '@arco-design/web-react';
import { IconSave, IconUndo } from '@arco-design/web-react/icon';
import * as api from '../api';
import type { Snapshot } from '../snapshot';
import TokenGenerator from '../components/TokenGenerator';

const { Row, Col } = Grid;

/* Network settings — the diverted office segment.
 *
 * This page is the only place in the console that edits something the Node
 * process does not own: client_subnet reaches iptables (TPROXY jump, DNS
 * hijack), nft (nft.conf), systemd (turnout-nft.service) and the data plane
 * (per-terminal pair groups). A save therefore restarts a unit and briefly interrupts
 * proxying, which is why it sits behind an explicit confirm that names the
 * old and new value.
 *
 * The client-side check mirrors validateClientSubnet in internal/api/network.go
 * closely enough to catch typos before a disruptive save. The server stays
 * the authority — in particular it rejects a subnet that does not contain
 * ingress_ip, which this cannot check without a CIDR library.
 */

function looksLikeCIDR(s: string): string | null {
  if (/\s/.test(s)) return '含空白';
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return '格式应为 a.b.c.d/NN';
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return '每段必须在 0–255 之间';
  const prefix = Number(m[5]);
  if (prefix > 32) return '前缀必须 ≤ 32';
  if (prefix < 8) return '前缀过小 —— 那会把近乎整个互联网都引流过来';
  if (prefix === 32) return '单个主机不能作为引流网段';
  // Host bits must be clear, mirroring the server: iptables would match the
  // network anyway, but the API would then report a subnet that is not the
  // one the rules use. Same arithmetic as net.IPNet.Contains.
  const ipNum = octets.reduce((acc, o) => acc * 256 + o, 0);
  const blockSize = 2 ** (32 - prefix);
  if (ipNum % blockSize !== 0) {
    const netNum = ipNum - (ipNum % blockSize);
    const fmt = (n: number) => [24, 16, 8, 0].map((sh) => Math.floor(n / 2 ** sh) % 256).join('.');
    return `主机位未清零 —— 应写作 ${fmt(netNum)}/${prefix}`;
  }
  return null;
}

export default function NetworkPage({ snap, reload }: { snap: Snapshot; reload: () => void }) {
  const net = snap.network?.data;
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);

  // Reseed only while clean, same rule as the whitelist editor: another
  // operator's change must not clobber an in-progress edit, but the field
  // should not stay stale forever either.
  const applied = net?.client_subnet ?? '';
  useEffect(() => {
    if (draft === '' && applied) setDraft(applied);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applied]);

  const clean = draft === applied;
  const problem = draft ? looksLikeCIDR(draft) : null;
  const canSave = !clean && !problem && !saving;

  const save = () => {
    if (!canSave) return;
    Modal.confirm({
      title: '重建防火墙规则？',
      content: (
        <div>
          <p>
            引流网段将从 <Tag>{applied}</Tag> 改为 <Tag color="orange">{draft}</Tag>。
          </p>
          <p className="small">
            保存后会依次：重写 gateway.yaml 与 /etc/turnout/env、重新渲染 nft.conf、重启
            turnout-nft.service、热重载 mihomo。重启期间有几秒不做代理转发；
            所有 per-terminal 分组会按新网段重建（按节点对复用，不再是每 IP 一组）。
          </p>
          <p className="small">请确认该值与防火墙 PBR 规则的 source-address 一致，否则终端流量不会到达本机。</p>
        </div>
      ),
      okText: '确认重建',
      cancelText: '取消',
      onOk: async () => {
        setSaving(true);
        try {
          await api.putNodeNetwork(draft);
          Message.success('已应用 ' + draft);
          reload();
        } catch (e) {
          // A 500 here can mean gateway.yaml was written but the live rules
          // were not — say so instead of implying nothing happened.
          Message.error((e as Error).message);
          reload();
        } finally {
          setSaving(false);
        }
      },
    });
  };

  return (
    <div className="page">
      {net?.api_token_source === 'yaml' && (
        <Alert
          className="mb"
          type="warning"
          content={
            <span>
              当前 token 来自 <code>gateway.yaml</code> 的 <code>api.token</code>（旧方式）：它会随{' '}
              <code>make redeploy</code> 拷到笔记本。在下方「控制面 token」轮换一次，即迁到节点本地的 0600 文件并清掉 yaml 里的值。
            </span>
          }
        />
      )}

      <Card
        bordered={false}
        className="mb"
        title="引流网段 / client_subnet"
        extra={<span className="dim">GET / PUT /api/node/network</span>}
      >
        {snap.network?.err && <Alert className="mb" type="error" content={snap.network.err} />}

        <Row gutter={16}>
          <Col span={12}>
            <div className="small dim mb">办公网段 CIDR（防火墙 PBR 的 source-address）</div>
            <Input
              value={draft}
              onChange={setDraft}
              placeholder="例如 10.1.3.0/24"
              status={problem ? 'error' : undefined}
              disabled={saving}
              onPressEnter={save}
            />
            {problem && (
              <div className="err small mt">
                {problem}
              </div>
            )}
          </Col>
          <Col span={12}>
            <div className="small dim mb">源地址必须是网络地址（主机位清零）</div>
            <Descriptions
              column={1}
              size="small"
              data={[
                { label: '当前生效', value: applied ? <Tag>{applied}</Tag> : <span className="dim">未知</span> },
                { label: '入口网卡', value: net?.ingress_iface || <span className="dim">—</span> },
                { label: '入口地址', value: net?.ingress_ip || <span className="dim">—</span> },
                { label: '监听地址', value: net?.api_listen || <span className="dim">—</span> },
                {
                  label: '控制面证书',
                  value: net?.api_tls ? (
                    <span>
                      {net.api_tls.auto_managed ? '自签（自动续期）' : '运维自备'}，到期 {net.api_tls.not_after.slice(0, 10)}
                    </span>
                  ) : (
                    <span className="err">未启用 TLS（仅限回环监听）</span>
                  ),
                },
                {
                  label: '证书 SAN',
                  value: net?.api_tls?.sans?.length ? (
                    <span className="small">{net.api_tls.sans.join('  ')}</span>
                  ) : (
                    <span className="dim">—</span>
                  ),
                },
              ]}
            />
          </Col>
        </Row>

        <Space className="mt">
          <Button type="primary" icon={<IconSave />} loading={saving} disabled={!canSave} onClick={save}>
            保存并重建规则
          </Button>
          <Button icon={<IconUndo />} disabled={clean || saving} onClick={() => setDraft(applied)}>
            撤销
          </Button>
          {!clean && <span className="small dim">未保存的修改</span>}
        </Space>
      </Card>

      <SignalCard snap={snap} reload={reload} />

      <TokenCard source={net?.api_token_source} />

      <Card bordered={false} title="这个值影响什么">
        <Descriptions
          column={1}
          size="small"
          data={[
            {
              label: 'iptables',
              value: 'TPROXY 跳转与 DNS 劫持的源地址匹配（-s client_subnet），只拦截这个网段的流量',
            },
            {
              label: 'nft',
              value: 'nft.conf 的 prerouting 链 —— 该网段的 DNS 直通 mihomo 的解析器',
            },
            {
              label: 'mihomo',
              value: 'per-terminal 分组按网段切分（同一节点对共用一组）；网段过大时按地址块聚合，不按单主机',
            },
            {
              label: '本机 18080',
              value: '目的地址是本机的流量不经过代理（TPROXY 链首条 --dst-type LOCAL 返回），该网段可直接访问控制面 —— 只走 HTTPS，明文请求会被跳转或拒绝',
            },
          ]}
        />
      </Card>
    </div>
  );
}

/* SignalCard — the watchdog knobs.
 *
 * liveness_ip is the address the firewall's IP-Link probe watches: present =
 * Up, absent = Down. It is held on lo (or the ingress NIC) by the kernel, not
 * by the process, which is the whole reason this card exists: an operator who
 * believes "the watchdog withdraws it when the process dies" is wrong, and the
 * copy below says so instead of hiding it.
 *
 * Two switches with genuinely different weight:
 *   notify_on_state_change — pure visibility, no risk. Fires on a check's
 *                            transition, message body names the failing check.
 *   auto_failover          — acts on the kernel. On unhealthy it REMOVES the
 *                            address, so the firewall stops diverting. This is
 *                            the one that can surprise: every manually
 *                            triggered save here restarts turnout-gateway, and
 *                            the address only comes back after
 *                            recover_threshold clean rounds.
 */
function SignalCard({ snap, reload }: { snap: Snapshot; reload: () => void }) {
  const sig = snap.signal?.data;
  const wd = snap.watchdog?.body;
  const [ip, setIp] = useState('');
  const [saving, setSaving] = useState(false);

  const applied = sig?.liveness_ip ?? '';
  useEffect(() => {
    if (ip === '' && applied) setIp(applied);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applied]);

  const ipDirty = ip !== applied;

  const ipProblem = ((): string | null => {
    if (!ipDirty) return null;
    if (!ip) return '不能为空 —— 没有它防火墙收不到任何健康信号';
    if (!/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(ip)) return '格式应为 a.b.c.d';
    const octets = ip.split('.').map(Number);
    if (octets.some((o) => o > 255)) return '每段必须在 0–255 之间';
    if (sig?.ingress_ip && ip === sig.ingress_ip) return `不能等于入口地址 ${sig.ingress_ip} —— 摘掉会把 SSH 和 API 一起断掉`;
    if (sig?.return_gateway && ip === sig.return_gateway) return `不能等于防火墙地址 ${sig.return_gateway}`;
    return null;
  })();

  const saveIp = () => {
    if (!ipDirty || ipProblem || saving) return;
    Modal.confirm({
      title: '更换探活地址并重启控制面？',
      content: (
        <div>
          <p>
            探活地址将从 <Tag>{applied || '无'}</Tag> 改为 <Tag color="orange">{ip}</Tag>。
          </p>
          <p className="small">
            保存后会立即从内核摘掉旧地址（否则两个 /32 会同时应答防火墙探测），
            随后 turnout-gateway 会在约 2 秒后自动重启。重启后需连续 3 轮自检全绿
            （约 30 秒）新地址才会挂上；这段时间防火墙看到的是 Down。
          </p>
          <p className="small">
            ⚠️ 防火墙 IP-Link 的探测目标必须先改成同一个地址，否则它会一直探测一个不存在的 IP。
          </p>
        </div>
      ),
      okText: '确认更换',
      cancelText: '取消',
      onOk: async () => {
        setSaving(true);
        try {
          await api.putNodeSignal({ liveness_ip: ip });
          Message.success('已保存，控制面即将重启');
          setTimeout(reload, 4000);
        } catch (e) {
          Message.error((e as Error).message);
        } finally {
          setSaving(false);
        }
      },
    });
  };

  const toggle = (field: 'auto_failover' | 'notify_on_state_change', next: boolean) => {
    const label = field === 'auto_failover' ? '自动回切' : '状态变化告警';
    const warn =
      field === 'auto_failover' && next
        ? '开启后：判定不健康会摘掉探活地址，防火墙 IP-Link 转 Down，办公流量自动回落直连。'
        : field === 'auto_failover'
          ? '关闭后：判定不健康只记录日志与告警，探活地址保持应答，需要你手动回切。'
          : '该开关只影响告警投递，不改变任何数据面行为。';
    Modal.confirm({
      title: `${next ? '开启' : '关闭'}${label}？`,
      content: <p className="small">{warn}保存后控制面会自动重启。</p>,
      okText: '确认',
      cancelText: '取消',
      onOk: async () => {
        setSaving(true);
        try {
          await api.putNodeSignal({ [field]: next });
          Message.success('已保存，控制面即将重启');
          setTimeout(reload, 4000);
        } catch (e) {
          Message.error((e as Error).message);
        } finally {
          setSaving(false);
        }
      },
    });
  };

  const state = wd?.state || 'unknown';
  const stateTag =
    state === 'healthy' ? (
      <Tag color="green">健康</Tag>
    ) : state === 'unhealthy' ? (
      <Tag color="red">不健康</Tag>
    ) : (
      <Tag>尚未判定</Tag>
    );

  return (
    <Card
      bordered={false}
      className="mb"
      title="节点信号 / watchdog"
      extra={<span className="dim">GET / PUT /api/node/signal</span>}
    >
      {snap.signal?.err && <Alert className="mb" type="error" content={snap.signal.err} />}

      <Row gutter={16}>
        <Col span={12}>
          <div className="small dim mb">探活地址（防火墙 IP-Link 的探测目标）</div>
          <Input
            value={ip}
            onChange={setIp}
            placeholder="例如 10.1.3.250"
            status={ipProblem ? 'error' : undefined}
            disabled={saving}
            onPressEnter={saveIp}
          />
          {ipProblem && <div className="err small mt">{ipProblem}</div>}
          <Space className="mt">
            <Button
              type="primary"
              icon={<IconSave />}
              loading={saving}
              disabled={!ipDirty || !!ipProblem}
              onClick={saveIp}
            >
              保存并重启
            </Button>
            <Button icon={<IconUndo />} disabled={!ipDirty || saving} onClick={() => setIp(applied)}>
              撤销
            </Button>
          </Space>
          <div className="small dim mt">
            绑定在 {sig?.liveness_iface || 'lo'} 上。★ 这个地址由内核持有，**进程崩溃不会自动摘除** ——
            真正的兜底是 systemd 的自动重启。
          </div>
        </Col>

        <Col span={12}>
          <Descriptions
            column={1}
            size="small"
            data={[
              { label: '当前判定', value: stateTag },
              {
                label: '地址在位',
                value: wd?.enabled === false ? <span className="dim">未启用</span> : wd?.liveness_up ? '是' : '否',
              },
              { label: '连续通过', value: wd?.ok_streak ?? '—' },
              { label: '连续失败', value: wd?.fail_streak ?? '—' },
              { label: '最近翻转', value: wd?.last_transition || <span className="dim">—</span> },
            ]}
          />
          <div className="mt">
            <Space direction="vertical" size={10} style={{ width: '100%' }}>
              <div>
                <Switch
                  checked={!!sig?.auto_failover}
                  disabled={saving || !sig}
                  onChange={(v) => toggle('auto_failover', v)}
                />
                <span style={{ marginLeft: 8 }}>自动回切（auto_failover）</span>
                <div className="small dim">
                  不健康时摘地址 → 防火墙 IP-Link Down → 流量回落直连。
                  {!sig?.auto_failover && ' 当前仅报信，故障需手动回切。'}
                </div>
              </div>
              <div>
                <Switch
                  checked={!!sig?.notify_on_state_change}
                  disabled={saving || !sig}
                  onChange={(v) => toggle('notify_on_state_change', v)}
                />
                <span style={{ marginLeft: 8 }}>状态变化告警（notify_on_state_change）</span>
                <div className="small dim">
                  单项检查翻转时推送，消息里带失败的具体检查项。无风险，建议开启。
                </div>
              </div>
            </Space>
          </div>
        </Col>
      </Row>

      {wd?.checks?.length ? (
        <Descriptions
          className="mt"
          column={1}
          size="small"
          data={wd.checks.map((c) => ({
            label: c.name,
            value: (
              <span className={c.skipped ? 'dim' : c.ok ? '' : 'v-bad'}>
                {c.skipped ? '跳过' : c.ok ? '通过' : '失败'}
                {c.detail ? <span className="small dim"> · {c.detail}</span> : null}
              </span>
            ),
          }))}
        />
      ) : null}

      {wd && !wd.auto_failover && (
        <Alert
          className="mt"
          type="info"
          content="auto_failover 关闭时，watchdog 只观测不动作：判定不健康也不会摘掉探活地址，防火墙会继续把办公网引流过来。"
        />
      )}
    </Card>
  );
}

/* TokenCard — rotate the control-plane token.
 *
 * The old token stops working the moment the server accepts the new one:
 * this tab switches over in api.rotateToken, other open tabs fall back to
 * the login card on their next refresh. Scripts on the node read the token
 * file and need nothing; a TURNOUT_TOKEN exported on a laptop must be
 * updated by hand.
 */
function TokenCard({ source }: { source?: 'file' | 'yaml' }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  // Remount the generator after each rotation so it shows a fresh token.
  const [round, setRound] = useState(0);

  const rotate = (next: string) => {
    Modal.confirm({
      title: '轮换控制面 token？',
      content: '旧 token 立即失效：其他已打开的控制台标签页会回到登录页，笔记本上 export 的 TURNOUT_TOKEN 需要更新。节点本机的脚本和 healthwatch 读 token 文件，不受影响。',
      okText: '轮换',
      onOk: async () => {
        setBusy(true);
        try {
          await api.rotateToken(next);
          Message.success('已轮换，新 token 已生效');
          setOpen(false);
          setRound((r) => r + 1);
        } catch (e) {
          Message.error((e as Error).message);
        } finally {
          setBusy(false);
        }
      },
    });
  };

  return (
    <Card
      bordered={false}
      className="mb"
      title="控制面 token"
      extra={<span className="dim">POST /api/auth/rotate</span>}
    >
      <Descriptions
        column={1}
        size="small"
        data={[
          {
            label: '存放位置',
            value:
              source === 'yaml' ? (
                <span className="err">gateway.yaml（旧方式，建议轮换）</span>
              ) : (
                <span>节点本地文件（0600，不随 redeploy 离开节点）</span>
              ),
          },
          { label: '忘记 token', value: <code>make reset-token NODE=ops@&lt;host&gt;</code> },
        ]}
      />
      {!open ? (
        <Button className="mt" onClick={() => setOpen(true)}>
          生成新 token…
        </Button>
      ) : (
        <div className="mt">
          <TokenGenerator key={round} confirmText="轮换为这个 token" busy={busy} onConfirm={rotate} />
          <Button className="mt" type="text" onClick={() => setOpen(false)}>
            取消
          </Button>
        </div>
      )}
    </Card>
  );
}
