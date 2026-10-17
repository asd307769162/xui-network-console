import { XUI_NODES } from '@/lib/xui';

export type CollectorIp = { ip: string; location?: string; firstSeen?: string; lastSeen?: string; online?: boolean; connections?: number; scanner?: boolean; scannedPorts?: number };
export type CollectorPort = { port: number; recent1h?: number; recent24h?: number; ips?: CollectorIp[] };

export function mainlandOnly(port: CollectorPort, now = Date.now()): CollectorPort {
  const ips = (port.ips || []).filter((entry) => {
    const location = entry.location || '';
    const country = location.split('·')[0].trim().toLowerCase();
    return ['中国', 'china', '中国大陆'].includes(country)
      && !/香港|澳门|澳門|台湾|臺灣|hong kong|macao|macau|taiwan/i.test(location);
  });
  const recent = (duration: number) => ips.filter((entry) => {
    const seen = Date.parse(entry.lastSeen || '');
    return !entry.scanner && Number.isFinite(seen) && seen <= now && now - seen <= duration;
  }).length;
  return { ...port, ips, recent1h: recent(3600_000), recent24h: recent(86400_000) };
}

export async function readCollector(node: (typeof XUI_NODES)[number]) {
  if (!('collectorUrl' in node)) return new Map<number, CollectorPort>();
  const token = process.env[`COLLECTOR_TOKEN_${node.alias.toUpperCase()}`] || process.env.COLLECTOR_TOKEN;
  if (!token) throw new Error('采集器凭据尚未配置');
  const response = await fetch(node.collectorUrl, {
    headers: { authorization: `Bearer ${token}` },
    cache: 'no-store',
    signal: AbortSignal.timeout(5_000),
  });
  if (!response.ok) throw new Error(`采集器返回 ${response.status}`);
  const payload = await response.json() as { ports?: CollectorPort[] };
  const now = Date.now();
  return new Map((payload.ports || []).map((port) => [Number(port.port), mainlandOnly(port, now)]));
}

export function publicIp(entry: CollectorIp) {
  return {
    ip: entry.ip,
    location: entry.location || '归属地查询中',
    firstSeen: entry.firstSeen,
    lastSeen: entry.lastSeen,
    online: entry.online,
    connections: entry.connections,
    scanner: entry.scanner,
    scannedPorts: entry.scannedPorts,
  };
}
