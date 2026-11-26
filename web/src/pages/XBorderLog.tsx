import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Collapse,
  Descriptions,
  Grid,
  Input,
  InputNumber,
  Message,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
} from '@arco-design/web-react';
import { IconSave, IconUndo } from '@arco-design/web-react/icon';
import * as api from '../api';
import type { XBorderLogSettings, XBorderLogView } from '../types';
import { fmtTime } from '../format';

const { Row, Col } = Grid;

/* Cross-border access log — one syslog record per connection that left
 * through an airport node (docs/design-crossborder-access-log.md).
 *
 * Saving applies in-process: the sender reconnects to the new address and
 * records still queued for the old one are carried over. Unlike the watchdog
 * settings on 「网段设置」, nothing restarts, so the firewall never sees the
 * liveness address flap because of a logging change.
 *
 * The status card polls on its own (every 5s while this page is open): the
 * header's 10s refresh does not include this endpoint, and "is the server
 * actually receiving" is the one question this page exists to answer.
 */

const STATUS_MS = 5000;
const FACILITIES = Array.from({ length: 8 }, (_, i) => 'local' + i);

/** Mirrors config.ValidateXBorderLog's address rule: host:port, [v6]:port. */
function addressProblem(s: string): string | null {
  const v = s.trim();
  if (!v) return '启用时必须填写，例如 10.0.0.50:514';
  const m = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/.exec(v);
  if (!m) return '格式应为 主机:端口，IPv6 写成 [地址]:端口';
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return '端口须在 1–65535 之间';
  return null;
}

function same(a: XBorderLogSettings, b: XBorderLogSettings) {
  return (Object.keys(a) as (keyof XBorderLogSettings)[]).every((k) => a[k] === b[k]);
}

export default function XBorderLogPage() {
  const [view, setView] = useState<XBorderLogView | null>(null);
  const [form, setForm] = useState<XBorderLogSettings | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const [busy, setBusy] = useState(false);

  // First load fills the form; later polls refresh only the status so an
  // operator mid-edit does not have their input overwritten.
  const load = useCallback(async (resetForm: boolean) => {
    try {
      const v = await api.getXBorderLog();
      setView(v);
      if (resetForm) setForm(v.config);
      setLoadErr('');
    } catch (e) {
      setLoadErr((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load(true);
    const t = setInterval(() => load(false), STATUS_MS);
    return () => clearInterval(t);
  }, [load]);

  const saved = view?.config;
  const st = view?.status;
  const levelOk = view ? ['info', 'debug'].includes(view.data_plane_log_level) : true;
  const dirty = !!form && !!saved && !same(form, saved);
  const addrProb = form?.enabled ? addressProblem(form.address) : null;
  const pollProb =
    form && (form.poll_interval_ms < 200 || form.poll_interval_ms > 10000) ? '采样间隔须在 200–10000 毫秒之间' : null;
  const queueProb = form && (form.queue_size < 100 || form.queue_size > 1000000) ? '队列须在 100–1000000 条之间' : null;
  const enableBlocked = !!form?.enabled && !levelOk;
  const canSave = dirty && !addrProb && !pollProb && !queueProb && !enableBlocked && !busy;

  const set = <K extends keyof XBorderLogSettings>(k: K, v: XBorderLogSettings[K]) =>
    setForm((f) => (f ? { ...f, [k]: v } : f));

  const doSave = async () => {
    if (!form || !saved) return;
    // Send only what changed: PUT is a patch, and an unchanged field echoed
    // back could overwrite a concurrent edit from another console.
    const patch: Partial<XBorderLogSettings> = {};
    (Object.keys(form) as (keyof XBorderLogSettings)[]).forEach((k) => {
      if (form[k] !== saved[k]) (patch as Record<string, unknown>)[k] = k === 'address' ? form.address.trim() : form[k];
    });
    setBusy(true);
    try {
      const v = await api.putXBorderLog(patch);
      setView(v);
      setForm(v.config);
      Message.success(v.config.enabled ? '已保存并生效，正在连接日志服务器' : '已保存，跨境访问日志已关闭');
    } catch (e) {
      Message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const save = () => {
    if (!canSave) return;
    if (saved?.enabled && form && !form.enabled) {
      Modal.confirm({
        title: '关闭跨境访问日志？',
        content: (
          <p className="small">
            关闭后，跨境访问将不再记录，期间的访问事后也无法补录。还没发出的
            {st?.queued ? ` ${st.queued} 条` : ''}记录会被丢弃。服务器地址会保留，下次开启无需重填。
          </p>
        ),
        okText: '确认关闭',
        cancelText: '取消',
        onOk: doSave,
      });
      return;
    }
    doSave();
  };

  const statusAlert = useMemo(() => {
    if (!view || !st) return null;
    if (!view.config.enabled) {
      return <Alert className="mb" type="warning" content="跨境访问日志未开启 —— 经海外节点的访问目前没有任何记录。" />;
    }
    if (st.connected) {
      return (
        <Alert
          className="mb"
          type="success"
          content={`正在记录，已连接日志服务器 ${view.config.address}。本次开启以来已发送 ${st.sent} 条。`}
        />
      );
    }
    return (
      <Alert
        className="mb"
        type="error"
        content={
          <>
            已开启，但连不上日志服务器 {view.config.address}。记录正在本机排队（{st.queued} / {st.queue_size}
            ），队列满后会丢弃最旧的。
            {st.last_error && <div className="small mono mt">{st.last_error}</div>}
          </>
        }
      />
    );
  }, [view, st]);

  if (!form || !view) {
    return (
      <div className="page">
        {loadErr ? <Alert type="error" content={loadErr} /> : <Card bordered={false} loading />}
      </div>
    );
  }

  return (
    <div className="page">
      {loadErr && <Alert className="mb" type="error" content={loadErr} />}
      {statusAlert}
      {!levelOk && (
        <Alert
          className="mb"
          type="warning"
          content={`mihomo 日志级别是 ${view.data_plane_log_level}，需要 info 或 debug 才能开启：短连接和拨号失败只出现在 info 日志里。请先把 gateway.yaml 的 data_plane.log_level 改为 info。`}
        />
      )}

      <Row gutter={16}>
        <Col span={14}>
          <Card bordered={false} className="mb" title="日志服务器" extra={<span className="dim">Syslog · TCP · RFC 5424</span>}>
            <Space className="mb">
              <Switch checked={form.enabled} onChange={(v) => set('enabled', v)} disabled={busy} />
              <span>{form.enabled ? '开启' : '关闭'}</span>
            </Space>

            <div className="small dim mb">服务器地址</div>
            <Input
              value={form.address}
              onChange={(v) => set('address', v)}
              placeholder="10.0.0.50:514"
              status={addrProb ? 'error' : undefined}
              disabled={busy}
            />
            {addrProb && <div className="err small mt">{addrProb}</div>}

            <Collapse bordered={false} className="mt">
              <Collapse.Item name="adv" header="高级设置（一般保持默认）">
                <div className="small dim mb">分帧方式</div>
                <Select value={form.framing} onChange={(v) => set('framing', v)} disabled={busy}>
                  <Select.Option value="lf">每条一行（lf，兼容性最好）</Select.Option>
                  <Select.Option value="octet-counting">长度前缀（octet-counting，RFC 6587）</Select.Option>
                </Select>

                <div className="small dim mb mt">Facility</div>
                <Select value={form.facility} onChange={(v) => set('facility', v)} disabled={busy}>
                  {FACILITIES.map((f) => (
                    <Select.Option key={f} value={f}>
                      {f}
                    </Select.Option>
                  ))}
                </Select>

                <div className="small dim mb mt">APP-NAME</div>
                <Input value={form.app_name} onChange={(v) => set('app_name', v)} disabled={busy} />

                <div className="small dim mb mt">连接采样间隔（毫秒）</div>
                <InputNumber
                  value={form.poll_interval_ms}
                  min={200}
                  max={10000}
                  step={100}
                  onChange={(v) => set('poll_interval_ms', Number(v))}
                  disabled={busy}
                />
                <div className="small dim mt">
                  连接的结束时间和字节数以最后一次采样为准；活不到一个间隔的短连接只记域名，没有字节数。调小会增加对 mihomo 的轮询。
                </div>
                {pollProb && <div className="err small mt">{pollProb}</div>}

                <div className="small dim mb mt">本机队列（条）</div>
                <InputNumber
                  value={form.queue_size}
                  min={100}
                  max={1000000}
                  step={1000}
                  onChange={(v) => set('queue_size', Number(v))}
                  disabled={busy}
                />
                <div className="small dim mt">服务器断开时记录在内存排队；按当前约 700 条/小时，1 万条约可撑 14 小时。网关重启会清空队列。</div>
                {queueProb && <div className="err small mt">{queueProb}</div>}
              </Collapse.Item>
            </Collapse>

            <Space className="mt">
              <Button type="primary" icon={<IconSave />} loading={busy} disabled={!canSave} onClick={save}>
                保存并生效
              </Button>
              <Button icon={<IconUndo />} disabled={!dirty || busy} onClick={() => setForm(saved!)}>
                撤销修改
              </Button>
            </Space>
            {enableBlocked && <div className="err small mt">mihomo 日志级别不满足要求，无法开启</div>}
            <div className="small dim mt">保存后立即生效，不重启网关，不影响上网。只改 gateway.yaml 的 xborder_log 一节。</div>
          </Card>
        </Col>

        <Col span={10}>
          <Card bordered={false} className="mb" title="发送状态" extra={<span className="dim">每 {STATUS_MS / 1000} 秒刷新</span>}>
            <Descriptions
              column={1}
              size="small"
              data={[
                {
                  label: '连接',
                  value: !st?.running ? (
                    <Tag>未运行</Tag>
                  ) : st.connected ? (
                    <Tag color="green">已连接</Tag>
                  ) : (
                    <Tag color="red">未连接</Tag>
                  ),
                },
                { label: '已发送', value: <span className="num">{st?.running ? st.sent : '—'}</span> },
                {
                  label: '队列中',
                  value: <span className="num">{st?.running ? `${st.queued} / ${st.queue_size}` : '—'}</span>,
                },
                {
                  label: '已丢弃',
                  value: st?.running ? (
                    st.dropped ? <Tag color="orange">{st.dropped}</Tag> : <span className="num">0</span>
                  ) : (
                    '—'
                  ),
                },
                { label: '最近发送', value: st?.last_sent_at ? fmtTime(st.last_sent_at) : '—' },
                { label: '记录序号', value: <span className="num">{st?.seq || '—'}</span> },
                { label: '本次开启', value: st?.since ? fmtTime(st.since) : '—' },
                {
                  label: '最近错误',
                  value: st?.last_error ? (
                    <span className="small mono">
                      {st.last_error_at ? fmtTime(st.last_error_at) + ' ' : ''}
                      {st.last_error}
                    </span>
                  ) : (
                    '—'
                  ),
                },
              ]}
            />
            <div className="small dim mt">计数从本次开启或网关重启起算。接收端可用记录里的 seq 是否连续判断有没有丢。</div>
          </Card>
        </Col>
      </Row>

      <Card bordered={false} title="记录了什么">
        <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
          <li>
            <b>记录范围</b>：经机场节点出墙的连接，以及经海外节点的拨号失败。国内直连、广告拦截、网关自身连接不记。
          </li>
          <li>
            <b>每条记录</b>：终端 IP 与端口、开始/结束时间与时长、域名、终端原本要连的 IP、端口、命中规则、出口池与代理链、出口节点及地区、上下行字节、结果与错误原文。
          </li>
          <li>
            <b>格式</b>：每条一行 JSON，MSGID 为 <code>close</code>（info）或 <code>dial_error</code>（warning）。
          </li>
          <li>
            <b>记不到</b>：URL 路径与内容、员工姓名（只有 IP）、海外侧实际连接的 IP；约 1/4 的短连接没有字节数。
          </li>
          <li>
            <b>注意</b>：传输未加密，日志含员工上网记录。
          </li>
        </ul>
      </Card>
    </div>
  );
}
