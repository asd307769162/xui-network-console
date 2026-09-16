import { publicIp, readCollector } from '@/lib/collector';
import { XUI_NODES } from '@/lib/xui';

export async function GET(request: Request) {
  try {
    const url = new URL(request.url);
    const alias = url.searchParams.get('alias')?.toLowerCase();
    const port = Number(url.searchParams.get('port'));
    const node = XUI_NODES.find((item) => item.alias === alias);
    if (!node || !Number.isInteger(port) || port < 1 || port > 65535) {
      return Response.json({ error: '服务器或端口参数无效' }, { status: 400 });
    }
    const observed = (await readCollector(node)).get(port);
    return Response.json({ ips: (observed?.ips || []).map(publicIp) }, { headers: { 'cache-control': 'private, max-age=5' } });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : 'IP 记录读取失败' }, { status: 502 });
  }
}
