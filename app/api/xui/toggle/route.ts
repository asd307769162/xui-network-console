import { setInboundEnabled } from '@/lib/xui';

export async function POST(request: Request) {
  try {
    const input = await request.json() as { alias?: unknown; id?: unknown; enabled?: unknown };
    if (typeof input.alias !== 'string' || !Number.isInteger(input.id) || typeof input.enabled !== 'boolean') {
      return Response.json({ error: '参数格式无效' }, { status: 400 });
    }
    const result = await setInboundEnabled(input.alias, Number(input.id), input.enabled);
    return Response.json({ ok: true, result, changedAt: new Date().toISOString() });
  } catch (error) {
    return Response.json({ error: error instanceof Error ? error.message : '操作失败' }, { status: 502 });
  }
}

