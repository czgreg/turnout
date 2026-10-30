/* Control-plane token helpers.
 *
 * The token is generated HERE, in the operator's browser, and the server
 * only checks its shape (internal/api/auth.go tokenPattern). Format:
 * "tgw_" + 32 random bytes as unpadded base64url = 47 characters. The
 * prefix makes a leaked token recognisable to secret scanners.
 *
 * Like the rest of the console, nothing here touches web storage.
 */

export const TOKEN_PATTERN = /^tgw_[A-Za-z0-9_-]{43}$/;

export function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64url = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return 'tgw_' + b64url;
}

/**
 * Copy text to the clipboard. The async Clipboard API needs a secure
 * context, and a page the operator reached by clicking through a
 * self-signed-certificate warning may not count as one — so fall back to
 * selecting a throwaway textarea and execCommand('copy').
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (window.isSecureContext && navigator.clipboard) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch {
    ok = false;
  }
  document.body.removeChild(ta);
  return ok;
}
