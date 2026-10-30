import { useState } from 'react';
import { Alert, Button, Checkbox, Input, Message, Space } from '@arco-design/web-react';
import { IconCopy, IconRefresh } from '@arco-design/web-react/icon';
import { copyText, generateToken, TOKEN_PATTERN } from '../token';

/* TokenGenerator — the "make a token, save it, confirm" block shared by the
 * setup page and the rotate card.
 *
 * The token appears exactly once, here. The confirm button stays disabled
 * until the operator ticks "已保存": after setup / rotate the node only has
 * the token in a 0600 file, so a token that was not saved means an SSH
 * session and `make reset-token` to get back in.
 *
 * allowExisting lets setup take a pasted token instead (one token shared by
 * several nodes); rotation always mints a fresh one.
 */

interface Props {
  confirmText: string;
  busy?: boolean;
  allowExisting?: boolean;
  /** Extra fields (e.g. setup code) rendered between token and confirm. */
  children?: React.ReactNode;
  /** Disable confirm until the parent's own fields are filled. */
  extraReady?: boolean;
  onConfirm: (token: string) => void;
}

export default function TokenGenerator({
  confirmText,
  busy,
  allowExisting,
  children,
  extraReady = true,
  onConfirm,
}: Props) {
  const [token, setToken] = useState(generateToken);
  const [saved, setSaved] = useState(false);
  const [useExisting, setUseExisting] = useState(false);
  const [pasted, setPasted] = useState('');

  const effective = useExisting ? pasted.trim() : token;
  const valid = TOKEN_PATTERN.test(effective);

  const regenerate = () => {
    setToken(generateToken());
    setSaved(false);
  };

  const copy = async () => {
    if (await copyText(token)) Message.success('已复制');
    else Message.warning('浏览器拒绝了复制，请手动选中文本复制');
  };

  return (
    <div className="token-gen">
      {!useExisting ? (
        <>
          <div className="small dim mb">新 token（只显示这一次）</div>
          <Input
            readOnly
            value={token}
            className="token-value"
            onFocus={(e) => (e.target as HTMLInputElement).select()}
          />
          <Space className="mt">
            <Button size="small" icon={<IconCopy />} onClick={copy}>
              复制
            </Button>
            <Button size="small" icon={<IconRefresh />} onClick={regenerate}>
              重新生成
            </Button>
          </Space>
        </>
      ) : (
        <>
          <div className="small dim mb">粘贴已有 token（tgw_ 开头，47 个字符）</div>
          <Input.Password
            value={pasted}
            onChange={(v) => {
              setPasted(v);
              setSaved(false);
            }}
            placeholder="tgw_..."
            autoComplete="off"
            status={pasted && !valid ? 'error' : undefined}
          />
          {pasted && !valid && <div className="err small mt">格式不对：应为 tgw_ 加 43 个 base64url 字符</div>}
        </>
      )}

      {allowExisting && (
        <div className="mt">
          <Button
            type="text"
            size="mini"
            onClick={() => {
              setUseExisting(!useExisting);
              setSaved(false);
            }}
          >
            {useExisting ? '改为生成新 token' : '使用已有 token（多个节点共用时）'}
          </Button>
        </div>
      )}

      <div className="mt">
        <Checkbox checked={saved} onChange={setSaved} disabled={!valid}>
          我已把这个 token 保存到密码管理器
        </Checkbox>
      </div>

      {children}

      <Alert
        className="mt"
        type="info"
        content="确认后立即生效。节点上只存这一份（0600 文件），丢了只能 SSH 上节点执行 make reset-token 重新初始化。"
      />

      <Button
        className="mt"
        type="primary"
        long
        size="large"
        loading={busy}
        disabled={!valid || !saved || !extraReady}
        onClick={() => onConfirm(effective)}
      >
        {confirmText}
      </Button>
    </div>
  );
}
