// Schema source for the bounded initial port-notes migration.
export const portNotesSchema = {
  table: 'port_notes',
  columns: { alias: 'TEXT NOT NULL', inbound_id: 'INTEGER NOT NULL', note: 'TEXT NOT NULL', updated_at: 'TEXT NOT NULL' },
  primaryKey: ['alias', 'inbound_id'],
} as const;

export const portFlagsSchema = {
  table: 'port_flags',
  columns: { alias: 'TEXT NOT NULL', inbound_id: 'INTEGER NOT NULL', trusted: 'INTEGER NOT NULL DEFAULT 0', observing: 'INTEGER NOT NULL DEFAULT 0', updated_at: 'TEXT NOT NULL' },
  primaryKey: ['alias', 'inbound_id'],
} as const;
