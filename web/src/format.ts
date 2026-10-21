// Display formatters. Kept tolerant of missing values: scorer-less nodes and
// never-probed candidates send 0 / null, which must read as "—", not "0ms".

export function fmtMs(v?: number | null): string {
  if (v == null || v === 0) return '—';
  return v >= 1000 ? (v / 1000).toFixed(2) + 's' : Math.round(v) + 'ms';
}

export function fmtRate(v?: number | null): string {
  if (v == null || v < 0) return '—';
  return (v * 100).toFixed(0) + '%';
}

const pad = (n: number) => String(n).padStart(2, '0');

export function fmtTime(s?: string | null): string {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d.getTime())) return s;
  return (
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
  );
}

export function fmtClock(d: Date): string {
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function ago(s?: string | null): string {
  if (!s) return '';
  const secs = Math.floor((Date.now() - new Date(s).getTime()) / 1000);
  if (isNaN(secs) || secs < 0) return '';
  if (secs < 60) return secs + ' 秒前';
  if (secs < 3600) return Math.floor(secs / 60) + ' 分钟前';
  if (secs < 86400) return Math.floor(secs / 3600) + ' 小时前';
  return Math.floor(secs / 86400) + ' 天前';
}

export function fmtUptime(secs?: number): string {
  if (!secs) return '—';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  return d ? `${d} 天 ${h} 小时` : `${h} 小时 ${Math.floor((secs % 3600) / 60)} 分`;
}

export function fmtSeconds(secs: number): string {
  if (secs === 0) return '关闭';
  if (secs % 3600 === 0) return secs / 3600 + ' 小时';
  if (secs % 60 === 0) return secs / 60 + ' 分钟';
  return secs + ' 秒';
}

/** Short tag text for a probe: "openai-api" → "openai", "accounts.google.com" → "google". */
export function probeLabel(name: string): string {
  const n = name.replace(/-api$/, '');
  const parts = n.split('.');
  return parts.length > 2 ? parts[parts.length - 2] : parts[0];
}

/** Node tags are "<subscription>/<node>"; split for two-line display. */
export function splitNode(tag: string): { sub: string; node: string } {
  const i = tag.indexOf('/');
  return i < 0 ? { sub: '', node: tag } : { sub: tag.slice(0, i), node: tag.slice(i + 1) };
}

/** Format bytes into a human-readable string: 1.23 GB, 456 MB, etc. */
export function fmtBytes(n?: number | null): string {
  if (n == null || n === 0) return '—';
  if (n >= 1e12) return (n / 1e12).toFixed(2) + ' TB';
  if (n >= 1e9) return (n / 1e9).toFixed(2) + ' GB';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + ' MB';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + ' KB';
  return n + ' B';
}

/**
 * Format a Unix timestamp (seconds) as a localized date string.
 * Returns "—" for 0 or null, "已到期" if the timestamp is in the past.
 */
export function fmtExpire(ts?: number | null): { text: string; expired: boolean } {
  if (!ts) return { text: '—', expired: false };
  const d = new Date(ts * 1000);
  const now = Date.now();
  if (d.getTime() < now) return { text: '已到期', expired: true };
  const pad = (n: number) => String(n).padStart(2, '0');
  const text =
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  // Show "剩 N 天" for the next 30 days
  const daysLeft = Math.ceil((d.getTime() - now) / 86400000);
  const suffix = daysLeft <= 30 ? ` (剩 ${daysLeft} 天)` : '';
  return { text: text + suffix, expired: false };
}
