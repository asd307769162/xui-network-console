import { env } from 'cloudflare:workers';

export function notesDatabase(): D1Database {
  const database = (env as unknown as { DB?: D1Database }).DB;
  if (!database) throw new Error('备注存储尚未配置');
  return database;
}
