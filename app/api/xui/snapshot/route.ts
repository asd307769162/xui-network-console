import { publicIp, readCollector } from '@/lib/collector';
import { XUI_NODES, listInbounds } from '@/lib/xui';

let cachedSnapshot: { expires: number; value: unknown } | undefined;
let pendingSnapshot: Promise<unknown> | undefined;

async function createSnapshot() {
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
          const allIps = observed?.ips || [];
          const activeIps = allIps.filter((entry) => entry.online !== false && !entry.scanner);
          const activeRegions = new Set(activeIps.map((entry) => (entry.location || '').split('·').slice(0, 3).join('·')));
          const activeNetworks = new Set(activeIps.map((entry) => (entry.location || '').split('·').slice(-2).join('·')));
          return ({
          id: Number(item.id),
          port: Number(item.port),
          protocol: String(item.protocol || 'unknown'),
          enabled: Boolean(item.enable),
          upload: Number(item.up || 0) / 1024 ** 3,
          download: Number(item.down || 0) / 1024 ** 3,
          ips: allIps.slice(0, 3).map(publicIp),
          totalIps: allIps.length,
          activeIpCount: activeIps.length,
          activeRegionCount: activeRegions.size,
          activeNetworkCount: activeNetworks.size,
          recent1h: observed?.recent1h,
          recent24h: observed?.recent24h,
        }); }),
      };
    } catch (error) {
      return { alias: node.alias.toUpperCase(), ip: new URL(node.url).hostname, region: error instanceof Error ? error.message : '读取失败', online: false, ports: [] };
    }
  }));
  return { nodes: results, collectedAt: new Date().toISOString() };
}

export async function GET() {
  const now = Date.now();
  if (cachedSnapshot && cachedSnapshot.expires > now) return Response.json(cachedSnapshot.value, { headers: { 'cache-control': 'private, max-age=5' } });
  pendingSnapshot ??= createSnapshot().then((value) => {
    cachedSnapshot = { expires: Date.now() + 5_000, value };
    return value;
  }).finally(() => { pendingSnapshot = undefined; });
  return Response.json(await pendingSnapshot, { headers: { 'cache-control': 'private, max-age=5' } });
}
