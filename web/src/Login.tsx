import { useEffect, useState } from 'react';
import { Alert, Button, Form, Input, Notification, Spin } from '@arco-design/web-react';
import { IconLock, IconMoonFill, IconSunFill, IconLink } from '@arco-design/web-react/icon';
import * as api from './api';
import type { AuthState } from './types';
import Logo from './components/Logo';
import TokenGenerator from './components/TokenGenerator';

interface Props {
  onConnected: () => void;
  initialError?: string;
  dark: boolean;
  onToggleTheme: () => void;
}

/* Login / first-time setup.
 *
 * The page asks GET /api/auth/state (unauthenticated) which of two cards to
 * show:
 *   - setup: the node has no token yet. The operator verifies the TLS
 *     fingerprint, generates a token here, saves it, and confirms with the
 *     one-time setup code from the node (or the ops Lark group). Without the
 *     code, whoever reached the page first after a deploy would own the node.
 *   - active: the usual login; the token is mandatory.
 */
export default function Login({ onConnected, initialError, dark, onToggleTheme }: Props) {
  const [form] = Form.useForm();
  const [err, setErr] = useState(initialError || '');
  const [busy, setBusy] = useState(false);

  // Same-origin default: when the control plane serves this page itself,
  // the API lives at location.origin.
  const defaultBase = location.protocol.startsWith('http') ? location.origin : '';
  const [base, setBase] = useState(defaultBase);
  const [state, setState] = useState<AuthState | null>(null);
  const [probing, setProbing] = useState(true);

  const probe = async (b: string) => {
    setProbing(true);
    setErr(initialError || '');
    api.connect(b, '');
    try {
      setState(await api.getAuthState());
    } catch (e) {
      // Unreachable or an older binary without /api/auth/state: fall back to
      // the plain login card and let the connect attempt report the error.
      setState(null);
      if (b) setErr((e as Error).message);
    } finally {
      setProbing(false);
    }
  };

  useEffect(() => {
    probe(defaultBase);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async (values: { base: string; token: string }) => {
    setBusy(true);
    setErr('');
    api.connect(values.base || '', values.token || '');
    try {
      await api.checkAuth(); // probe once: address + token both usable
      form.setFieldValue('token', ''); // do not leave it in the DOM
      onConnected();
    } catch (e) {
      api.disconnect();
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <Button
        className="login-theme"
        shape="circle"
        icon={dark ? <IconSunFill /> : <IconMoonFill />}
        onClick={onToggleTheme}
        aria-label="切换主题"
      />
      <div className="login-hero">
        <Logo size={56} />
        <h1>Turnout</h1>
        <p className="login-cn">道岔网关 · 控制台</p>
        <p className="login-tag">
          旁挂在办公网防火墙上，逐条流量判定走哪条道 —— 员工零配置、零客户端、零感知。
        </p>
        <ul className="login-points">
          <li>节点打分与站点探针，实时可见</li>
          <li>订阅增删改，一处完成</li>
          <li>按终端 IP 秒查出口</li>
        </ul>
      </div>

      {probing ? (
        <div className="login-card">
          <Spin tip="正在检测节点状态…" />
        </div>
      ) : state?.state === 'setup' ? (
        <SetupCard base={base} state={state} onDone={onConnected} onRecheck={() => probe(base)} />
      ) : (
        <div className="login-card">
          <h2>连接到节点</h2>
          <p className="login-hint">
            token 只保存在当前标签页内存里，不写入任何浏览器存储，刷新页面需要重新输入。
          </p>
          {state?.token_source === 'yaml' && (
            <Alert
              className="mb"
              type="warning"
              content="这个节点的 token 还在 gateway.yaml 里（旧方式，会随 make redeploy 拷到笔记本）。登录后到「网段设置」轮换一次即可迁到节点本地文件。"
            />
          )}
          <Form
            form={form}
            layout="vertical"
            onSubmit={submit}
            initialValues={{ base: defaultBase, token: '' }}
            autoComplete="off"
          >
            <Form.Item label="控制面地址" field="base" extra="默认取当前页面同源">
              <Input
                prefix={<IconLink />}
                placeholder="https://<node-ip>:18080"
                onChange={setBase}
                onBlur={() => base !== defaultBase && probe(base)}
              />
            </Form.Item>
            <Form.Item label="API Token" field="token" rules={[{ required: true, message: '必填' }]}>
              <Input.Password prefix={<IconLock />} placeholder="tgw_..." autoComplete="current-password" />
            </Form.Item>
            {err && <Alert type="error" content={err} className="login-err" />}
            <Button type="primary" htmlType="submit" long loading={busy} size="large">
              连接
            </Button>
          </Form>
        </div>
      )}
    </div>
  );
}

function SetupCard({
  base,
  state,
  onDone,
  onRecheck,
}: {
  base: string;
  state: AuthState;
  onDone: () => void;
  onRecheck: () => void;
}) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const host = (() => {
    try {
      return new URL(base || location.origin).hostname;
    } catch {
      return '<node-ip>';
    }
  })();

  const confirm = async (token: string) => {
    setBusy(true);
    setErr('');
    api.connect(base, '');
    try {
      await api.setupAuth(token, code);
      api.connect(base, token);
      Notification.success({
        title: '控制台已初始化',
        duration: 12000,
        content:
          '节点上的脚本和 healthwatch 自动读取 token 文件；笔记本上的 make status 等经 ssh 读取，' +
          '也可以 export TURNOUT_TOKEN=<token> 覆盖。',
      });
      onDone();
    } catch (e) {
      const msg = (e as Error).message;
      // 409: someone else completed setup in the meantime.
      if (msg.startsWith('409')) {
        setErr('节点已被初始化（可能是别人刚刚完成）。如果不是你们团队的操作，立即 make reset-token。');
        onRecheck();
      } else {
        setErr(msg);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-card">
      <h2>初始化控制台</h2>
      <p className="login-hint">这个节点还没有 API token，控制面在初始化完成前对所有请求关闭。</p>

      <Alert
        type="warning"
        className="mb"
        title="第一步：核对证书指纹"
        content={
          <span>
            点地址栏的证书信息，查看 SHA-256 指纹，与 <code>make tls-info NODE=ops@{host}</code>、setup code
            文件里的 <code>tls_fingerprint_sha256</code> 或飞书消息里的指纹逐段比对。
            <b>不一致就停下</b>：说明连接被劫持，提交的 setup code 和 token 会落到对方手里。
          </span>
        }
      />

      <TokenGenerator
        confirmText="确认启用"
        busy={busy}
        allowExisting
        extraReady={code.trim().length >= 20}
        onConfirm={confirm}
      >
        <div className="mt">
          <div className="small dim mb">setup code（一次性，节点每次重启都会换）</div>
          <Input
            value={code}
            onChange={setCode}
            placeholder="XXXX-XXXX-XXXX-XXXX-XXXX"
            autoComplete="off"
            spellCheck={false}
          />
          <div className="small dim mt">
            获取：<code>make setup-code NODE=ops@{host}</code>，或在节点上{' '}
            <code>sudo cat {state.setup_code_hint || '/var/lib/turnout/api-setup-code'}</code>
            {state.lark_delivered && <span>；也已发到运维飞书群</span>}
          </div>
        </div>
      </TokenGenerator>

      {err && <Alert type="error" content={err} className="login-err mt" />}
    </div>
  );
}
