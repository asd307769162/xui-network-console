import { XUI_NODES } from '@/lib/xui';

export type CollectorIp = { ip: string; location?: string; firstSeen?: string; lastSeen?: string; online?: boolean; connections?: number; scanner?: boolean; scannedPorts?: number };
export type CollectorPort = { port: number; recent1h?: number; recent24h?: number; ips?: CollectorIp[] };

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
  return new Map((payload.ports || []).map((port) => [Number(port.port), port]));
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
