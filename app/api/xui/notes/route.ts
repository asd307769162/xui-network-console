import { notesDatabase } from '@/lib/port-notes';
import { XUI_NODES } from '@/lib/xui';

export async function GET() {
  try {
    const { results } = await notesDatabase().prepare('SELECT alias, inbound_id, note FROM port_notes').all<{ alias: string; inbound_id: number; note: string }>();
    return Response.json({ notes: Object.fromEntries(results.map((row) => [`${row.alias}:${row.inbound_id}`, row.note])) }, { headers: { 'cache-control': 'no-store' } });
  } catch {
    return Response.json({ error: '备注读取失败，请检查存储配置' }, { status: 503 });
  }
}

export async function POST(request: Request) {
  try {
    const input = await request.json() as { alias?: unknown; id?: unknown; note?: unknown };
    if (typeof input.alias !== 'string' || !XUI_NODES.some((node) => node.alias === input.alias!.toString().toLowerCase()) || !Number.isSafeInteger(input.id) || Number(input.id) <= 0 || typeof input.note !== 'string' || input.note.length > 2000) {
      return Response.json({ error: '备注参数无效，最多可输入 2000 字' }, { status: 400 });
    }
    const alias = input.alias.toLowerCase();
    await notesDatabase().prepare('INSERT INTO port_notes (alias, inbound_id, note, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(alias, inbound_id) DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at').bind(alias, input.id, input.note, new Date().toISOString()).run();
    return Response.json({ ok: true, note: input.note });
  } catch {
    return Response.json({ error: '备注保存失败，请稍后重试' }, { status: 503 });
  }
}
