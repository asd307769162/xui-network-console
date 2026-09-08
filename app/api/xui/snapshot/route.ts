import { XUI_NODES, listInbounds } from '@/lib/xui';

export async function GET() {
  const results = await Promise.all(XUI_NODES.map(async (node) => {
    try {
      const { inbounds } = await listInbounds(node.alias);
      return {
        alias: node.alias.toUpperCase(),
        ip: new URL(node.url).hostname,
        region: '待采集代理回传',
        online: true,
        ports: inbounds.map((item) => ({
          id: Number(item.id),
          port: Number(item.port),
          protocol: String(item.protocol || 'unknown'),
          enabled: Boolean(item.enable),
          upload: Number(item.up || 0) / 1024 ** 3,
          download: Number(item.down || 0) / 1024 ** 3,
          ips: [],
        })),
      };
    } catch (error) {
      return { alias: node.alias.toUpperCase(), ip: new URL(node.url).hostname, region: error instanceof Error ? error.message : '读取失败', online: false, ports: [] };
    }
  }));
  return Response.json({ nodes: results, collectedAt: new Date().toISOString() });
}

