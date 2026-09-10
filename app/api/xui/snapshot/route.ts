import { XUI_NODES, listInbounds } from '@/lib/xui';

type CollectorIp = { ip: string; location?: string; firstSeen?: string; lastSeen?: string; online?: boolean; connections?: number; scanner?: boolean; scannedPorts?: number };
type CollectorPort = { port: number; recent1h?: number; recent24h?: number; ips?: CollectorIp[] };

async function readCollector(node: (typeof XUI_NODES)[number]) {
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

export async function GET() {
  const results = await Promise.all(XUI_NODES.map(async (node) => {
    try {
      const [{ inbounds }, collected] = await Promise.all([listInbounds(node.alias), readCollector(node)]);
      return {
        alias: node.alias.toUpperCase(),
        ip: new URL(node.url).hostname,
        region: '待采集代理回传',
        online: true,
        ports: inbounds.map((item) => {
          const observed = collected.get(Number(item.port));
          return ({
          id: Number(item.id),
          port: Number(item.port),
          protocol: String(item.protocol || 'unknown'),
          enabled: Boolean(item.enable),
          upload: Number(item.up || 0) / 1024 ** 3,
          download: Number(item.down || 0) / 1024 ** 3,
          ips: (observed?.ips || []).map((entry) => ({
            ip: entry.ip,
            location: entry.location || '归属地查询中',
            firstSeen: entry.firstSeen,
            lastSeen: entry.lastSeen,
            online: entry.online,
            connections: entry.connections,
            scanner: entry.scanner,
            scannedPorts: entry.scannedPorts,
          })),
          recent1h: observed?.recent1h,
          recent24h: observed?.recent24h,
        }); }),
      };
    } catch (error) {
      return { alias: node.alias.toUpperCase(), ip: new URL(node.url).hostname, region: error instanceof Error ? error.message : '读取失败', online: false, ports: [] };
    }
  }));
  return Response.json({ nodes: results, collectedAt: new Date().toISOString() });
}
