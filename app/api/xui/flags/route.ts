import { notesDatabase } from '@/lib/port-notes';
import { XUI_NODES } from '@/lib/xui';

export async function GET() {
  try {
    const { results } = await notesDatabase().prepare('SELECT alias, inbound_id, trusted, observing FROM port_flags').all<{ alias: string; inbound_id: number; trusted: number; observing: number }>();
    return Response.json({ flags: Object.fromEntries(results.map((row) => [`${row.alias}:${row.inbound_id}`, { trusted: Boolean(row.trusted), observing: Boolean(row.observing) }])) }, { headers: { 'cache-control': 'no-store' } });
  } catch {
    return Response.json({ error: '处理标记读取失败，请检查存储配置' }, { status: 503 });
  }
}

export async function POST(request: Request) {
  try {
    const input = await request.json() as { alias?: unknown; id?: unknown; trusted?: unknown; observing?: unknown };
    if (typeof input.alias !== 'string' || !XUI_NODES.some((node) => node.alias === input.alias!.toLowerCase()) || !Number.isSafeInteger(input.id) || Number(input.id) <= 0 || typeof input.trusted !== 'boolean' || typeof input.observing !== 'boolean') {
      return Response.json({ error: '处理标记参数无效' }, { status: 400 });
    }
    const alias = input.alias.toLowerCase();
    const database = notesDatabase();
    if (!input.trusted && !input.observing) {
      await database.prepare('DELETE FROM port_flags WHERE alias = ? AND inbound_id = ?').bind(alias, input.id).run();
    } else {
      await database.prepare('INSERT INTO port_flags (alias, inbound_id, trusted, observing, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(alias, inbound_id) DO UPDATE SET trusted = excluded.trusted, observing = excluded.observing, updated_at = excluded.updated_at').bind(alias, input.id, Number(input.trusted), Number(input.observing), new Date().toISOString()).run();
    }
    return Response.json({ ok: true, flags: { trusted: input.trusted, observing: input.observing } });
  } catch {
    return Response.json({ error: '处理标记保存失败，请稍后重试' }, { status: 503 });
  }
}
