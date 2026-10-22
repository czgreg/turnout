import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Empty,
  Grid,
  Input,
  Message,
  Modal,
  Space,
  Switch,
  Table,
  Tag,
} from '@arco-design/web-react';
import { IconSave, IconSend, IconDelete, IconRefresh } from '@arco-design/web-react/icon';
import * as api from '../api';
import type { NotificationEntry, NotificationsStatus } from '../types';

const { Row, Col } = Grid;

/* Notifications — the Lark webhook and the local delivery log.
 *
 * Two things this page must not misrepresent:
 *
 * 1. The signing secret never round-trips. The server returns only
 *    `secret_configured: boolean`; leaving the field blank on save means
 *    "keep the stored secret", not "clear it". Clearing is the separate
 *    DELETE action, which also removes the webhook URL.
 *
 * 2. `signature_required` defaults to TRUE on the server, and then a secret
 *    is mandatory. The form mirrors that default so the operator does not
 *    discover it as a 400.
 *
 * The log below is the ground truth for "did the alert go out": every attempt
 * is written to JSONL before the webhook fires, including failures. A node
 * that looks silent in Lark may still have rows here.
 */

const OUTCOME_TONE: Record<string, string> = {
  delivered: 'green',
  queued: 'arcoblue',
  webhook_failed: 'red',
};

function outcomeTag(outcome: string) {
  if (outcome.startsWith('dropped')) return <Tag color="orange">{outcome}</Tag>;
  return <Tag color={OUTCOME_TONE[outcome] || 'gray'}>{outcome}</Tag>;
}

/** Mirrors the server: a webhook URL, not a bare token. */
function urlProblem(s: string): string | null {
  if (!s) return null; // untouched
  if (!/^https?:\/\//.test(s)) return '需要以 http(s):// 开头的完整地址';
  if (!s.includes('/hook/')) return '看起来不是飞书机器人地址（路径里应包含 /hook/）';
  return null;
}

export default function NotificationsPage() {
  const [status, setStatus] = useState<NotificationsStatus | null>(null);
  const [entries, setEntries] = useState<NotificationEntry[] | null>(null);
  const [loadErr, setLoadErr] = useState('');
  const [busy, setBusy] = useState(false);

  const [url, setUrl] = useState('');
  const [secret, setSecret] = useState('');
  const [sigRequired, setSigRequired] = useState(true);

  const load = useCallback(async () => {
    try {
      const [st, log] = await Promise.all([
        api.getNotificationsStatus(),
        api.getNotificationLog(100),
      ]);
      setStatus(st);
      setEntries(log.entries || []);
      setSigRequired(st.signature_required);
      setLoadErr('');
    } catch (e) {
      setLoadErr((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const uProb = urlProblem(url);
  const secretMissing = sigRequired && !secret && !status?.secret_configured;
  const canSave = !!url && !uProb && !secretMissing && !busy;

  const save = async () => {
    if (!canSave) return;
    setBusy(true);
    try {
      const st = await api.setLark({
        webhook_url: url.trim(),
        // Empty means "keep the stored secret" — the server persists whatever
        // it receives, so sending "" when one already exists would wipe it.
        ...(secret ? { secret } : {}),
        signature_required: sigRequired,
      });
      setStatus(st);
      setUrl('');
      setSecret('');
      Message.success('已保存，通知已启用');
      load();
    } catch (e) {
      Message.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    try {
      await api.testNotification();
      Message.success('测试消息已发送，请检查飞书');
    } catch (e) {
      Message.error((e as Error).message);
    } finally {
      setBusy(false);
      load();
    }
  };

  const clear = () => {
    Modal.confirm({
      title: '清除飞书配置？',
      content: (
        <p className="small">
          会删除 gateway.yaml 里的 webhook 地址和本机保存的签名密钥（
          {status?.webhook_configured ? '当前已配置' : '当前未配置'}）。本地 JSONL 日志保留。
        </p>
      ),
      okText: '确认清除',
      cancelText: '取消',
      onOk: async () => {
        setBusy(true);
        try {
          const st = await api.clearLark();
          setStatus(st);
          Message.success('已清除');
          load();
        } catch (e) {
          Message.error((e as Error).message);
        } finally {
          setBusy(false);
        }
      },
    });
  };

  const configured = !!status?.webhook_configured;
  const enabled = !!status?.enabled && configured;

  return (
    <div className="page">
      {loadErr && <Alert className="mb" type="error" content={loadErr} />}

      <Alert
        className="mb"
        type={enabled ? 'success' : 'warning'}
        content={
          enabled
            ? '通知已启用。watchdog / 池变更 / 节点死亡等事件会推送到飞书。'
            : configured
              ? '已配置 webhook，但通知子系统未启用。保存一次配置或检查 notifications.enabled。'
              : '尚未配置飞书机器人 —— 所有告警目前只会写进本地日志，不会推送。'
        }
      />

      <Card
        bordered={false}
        className="mb"
        title="飞书机器人"
        extra={<span className="dim">POST /api/notifications/lark</span>}
      >
        <Row gutter={16}>
          <Col span={14}>
            <div className="small dim mb">Webhook 地址</div>
            <Input
              value={url}
              onChange={setUrl}
              placeholder={configured ? '已配置 —— 留空则保持现有地址' : 'https://open.feishu.cn/open-apis/bot/v2/hook/…'}
              status={uProb ? 'error' : undefined}
              disabled={busy}
            />
            {uProb && <div className="err small mt">{uProb}</div>}

            <div className="small dim mb mt">签名校验</div>
            <Space>
              <Switch checked={sigRequired} onChange={setSigRequired} disabled={busy} />
              <span className="small">
                {sigRequired ? '开启（需要签名密钥，推荐）' : '关闭（机器人未开启签名校验时）'}
              </span>
            </Space>

            <div className="small dim mb mt">签名密钥</div>
            <Input.Password
              value={secret}
              onChange={setSecret}
              placeholder={status?.secret_configured ? '已保存 —— 留空则保持现有密钥' : '飞书机器人的签名密钥'}
              disabled={busy || !sigRequired}
              status={secretMissing ? 'error' : undefined}
            />
            {secretMissing && <div className="err small mt">开启签名校验后必须提供密钥</div>}
          </Col>

          <Col span={10}>
            <Descriptions
              column={1}
              size="small"
              data={[
                { label: '通知启用', value: enabled ? <Tag color="green">是</Tag> : <Tag>否</Tag> },
                {
                  label: 'Webhook',
                  value: configured ? <Tag color="green">已配置</Tag> : <Tag color="orange">未配置</Tag>,
                },
                {
                  label: '签名密钥',
                  value: status?.secret_configured ? <Tag color="green">已保存</Tag> : <Tag>无</Tag>,
                },
                { label: '去重窗口', value: status?.dedup_window_sec != null ? status.dedup_window_sec + ' 秒' : '—' },
                {
                  label: '单节点限流',
                  value:
                    status?.per_node_rate_limit_per_hour != null
                      ? status.per_node_rate_limit_per_hour + ' 条/小时'
                      : '—',
                },
                { label: '重试次数', value: status?.retry_attempts ?? '—' },
                { label: '本地日志', value: <span className="small">{status?.local_log_path || '—'}</span> },
              ]}
            />
            <div className="small dim mt">
              ★ 密钥单独存放在 0600 文件里，不写进 gateway.yaml，也不会通过 API 回显。
            </div>
          </Col>
        </Row>

        <Space className="mt">
          <Button type="primary" icon={<IconSave />} loading={busy} disabled={!canSave} onClick={save}>
            保存
          </Button>
          <Button icon={<IconSend />} loading={busy} disabled={!configured || busy} onClick={test}>
            发送测试
          </Button>
          <Button icon={<IconDelete />} loading={busy} disabled={!configured || busy} onClick={clear}>
            清除配置
          </Button>
        </Space>
      </Card>

      <Card
        bordered={false}
        title="最近通知"
        extra={
          <Button size="mini" icon={<IconRefresh />} onClick={load} disabled={busy}>
            刷新
          </Button>
        }
      >
        {entries === null ? (
          <Empty description="加载中…" />
        ) : entries.length === 0 ? (
          <Empty description="还没有任何通知记录 —— 可能是尚未触发过告警，或本地日志刚被轮转" />
        ) : (
          <Table
            size="small"
            border={false}
            pagination={{ pageSize: 15, sizeCanChange: false }}
            data={entries.map((e, i) => ({ ...e, key: i }))}
            columns={[
              {
                title: '时间',
                dataIndex: 'at',
                width: 170,
                render: (v: string) => <span className="num small">{v ? new Date(v).toLocaleString() : '—'}</span>,
              },
              { title: '结果', dataIndex: 'outcome', width: 150, render: (v: string) => outcomeTag(v) },
              { title: '类型', dataIndex: 'type', width: 130, render: (v: string) => v || '—' },
              { title: '节点', dataIndex: 'node', width: 130, render: (v: string) => v || <span className="dim">—</span> },
              {
                title: '标题',
                dataIndex: 'subject',
                render: (v: string, r: NotificationEntry) => v || r.body || '—',
              },
            ]}
            expandedRowRender={(r: NotificationEntry) =>
              r.body || r.extra ? (
                <div className="small">
                  {r.body && <div style={{ whiteSpace: 'pre-wrap' }}>{r.body}</div>}
                  {r.extra && (
                    <pre className="small" style={{ margin: '8px 0 0', overflowX: 'auto' }}>
                      {JSON.stringify(r.extra, null, 2)}
                    </pre>
                  )}
                </div>
              ) : null
            }
          />
        )}
      </Card>

      <Card bordered={false} className="mt" title="和 watchdog 的关系">
        <p className="small">
          本页只负责「消息往哪儿送」。要不要在健康状态翻转时送，由
          <a href="#/network">「网段设置」</a>页的 <code>notify_on_state_change</code> 开关决定；
          那个开关关闭时，即使这里配置完整也不会收到任何 watchdog 告警。
        </p>
      </Card>
    </div>
  );
}
